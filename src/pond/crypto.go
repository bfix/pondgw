package pond

import (
	"bytes"
	"code.google.com/p/go.crypto/nacl/box"
	"code.google.com/p/goprotobuf/proto"
	"crypto/sha256"
	"encoding/binary"
	pond "github.com/agl/pond/protos"
	"github.com/bfix/gospel/logger"
	"io"
	"time"
)

const (
	nonceLen               = 24
	ephemeralBlockLen      = nonceLen + 32 + box.Overhead
)

var revocationSignaturePrefix = []byte("revocation\x00")

func (c *Client) decryptMessage(sealed []byte, from *Contact) ([]byte, bool) {
	if from.ratchet != nil {
		plaintext, err := from.ratchet.Decrypt(sealed)
		if err != nil {
			return nil, false
		}
		return plaintext, true
	}

	var nonce [24]byte
	if len(sealed) < len(nonce) {
		return nil, false
	}
	copy(nonce[:], sealed)
	sealed = sealed[24:]
	headerLen := ephemeralBlockLen - len(nonce)
	if len(sealed) < headerLen {
		return nil, false
	}

	publicBytes, ok := c.decryptMessageInner(sealed[:headerLen], &nonce, from)
	if !ok || len(publicBytes) != 32 {
		return nil, false
	}
	var innerNonce [nonceLen]byte
	sealed = sealed[headerLen:]
	copy(innerNonce[:], sealed)
	sealed = sealed[nonceLen:]
	var ephemeralPublicKey [32]byte
	copy(ephemeralPublicKey[:], publicBytes)

	if plaintext, ok := box.Open(nil, sealed, &innerNonce, &ephemeralPublicKey, &from.lastDHPrivate); ok {
		return plaintext, ok
	}

	plaintext, ok := box.Open(nil, sealed, &innerNonce, &ephemeralPublicKey, &from.currentDHPrivate)
	if !ok {
		return nil, false
	}

	copy(from.lastDHPrivate[:], from.currentDHPrivate[:])
	if _, err := io.ReadFull(c.prng, from.currentDHPrivate[:]); err != nil {
		panic(err)
	}
	return plaintext, true
}

func (c *Client) decryptMessageInner(sealed []byte, nonce *[24]byte, from *Contact) ([]byte, bool) {
	if plaintext, ok := box.Open(nil, sealed, nonce, &from.theirLastDHPublic, &from.lastDHPrivate); ok {
		return plaintext, true
	}

	if plaintext, ok := box.Open(nil, sealed, nonce, &from.theirCurrentDHPublic, &from.lastDHPrivate); ok {
		return plaintext, true
	}

	plaintext, ok := box.Open(nil, sealed, nonce, &from.theirLastDHPublic, &from.currentDHPrivate)
	if !ok {
		plaintext, ok = box.Open(nil, sealed, nonce, &from.theirCurrentDHPublic, &from.currentDHPrivate)
		if !ok {
			return nil, false
		}
	}

	copy(from.lastDHPrivate[:], from.currentDHPrivate[:])
	if _, err := io.ReadFull(c.prng, from.currentDHPrivate[:]); err != nil {
		panic(err)
	}
	return plaintext, true
}

func (c *Client) unsealMessage(inboxMsg *InboxMessage, from *Contact) bool {
	if from.isPending {
		logger.Println(logger.ERROR, "was asked to unseal message from pending contact")
		panic(0)
	}

	sealed := inboxMsg.sealed
	plaintext, ok := c.decryptMessage(sealed, from)

	if !ok {
		logger.Println(logger.WARN, "Failed to decrypt message")
		return false
	}

	if len(plaintext) < 4 {
		logger.Println(logger.WARN, "Plaintext too small to process")
		return false
	}

	mLen := int(binary.LittleEndian.Uint32(plaintext[:4]))
	plaintext = plaintext[4:]
	if mLen < 0 || mLen > len(plaintext) {
		logger.Printf(logger.WARN, "Plaintext length incorrect: %d\n", mLen)
		return false
	}
	plaintext = plaintext[:mLen]

	msg := new(pond.Message)
	if err := proto.Unmarshal(plaintext, msg); err != nil {
		logger.Println(logger.WARN, "Failed to parse message: "+err.Error())
		return false
	}

	for _, candidate := range c.inbox {
		if candidate.from == from.id &&
			candidate.id != inboxMsg.id &&
			candidate.message != nil &&
			*candidate.message.Id == *msg.Id {
			logger.Printf(logger.WARN, "Dropping duplicate message from %s\n", from.name)
			return false
		}
	}

	if from.ratchet == nil {
		if l := len(msg.MyNextDh); l != len(from.theirCurrentDHPublic) {
			logger.Printf(logger.WARN, "Bad Diffie-Hellman value length: %d", l)
			return false
		}

		if !bytes.Equal(from.theirCurrentDHPublic[:], msg.MyNextDh) {
			copy(from.theirLastDHPublic[:], from.theirCurrentDHPublic[:])
			copy(from.theirCurrentDHPublic[:], msg.MyNextDh)
		}
	}

	var ackedIds []uint64
	ackedIds = append(ackedIds, msg.AlsoAck...)
	if msg.InReplyTo != nil {
		ackedIds = append(ackedIds, *msg.InReplyTo)
	}

	var now time.Time
	if len(ackedIds) > 0 {
		now = time.Now()
	}

	for _, ackedId := range ackedIds {
		for _, candidate := range c.outbox {
			if candidate.id == ackedId {
				candidate.acked = now
				break
			}
		}
	}

	if msg.SupportedVersion != nil {
		from.supportedVersion = *msg.SupportedVersion
	}

	from.kxsBytes = nil
	inboxMsg.message = msg
	inboxMsg.sealed = nil
	inboxMsg.read = false

	return true
}

func (c *Client) processSigningRequest(sigReq SigningRequest) {
	defer close(sigReq.resultChan)
	to := c.contacts[sigReq.msg.to]

	messageBytes, err := proto.Marshal(sigReq.msg.message)
	if err != nil {
		logger.Printf(logger.ERROR, "Failed to sign outgoing message: %s\n", err)
		return
	}
	if len(messageBytes) > pond.MaxSerializedMessage {
		logger.Println(logger.ERROR, "Failed to sign outgoing message because it's too large")
		return
	}

	plaintext := make([]byte, pond.MaxSerializedMessage+4)
	binary.LittleEndian.PutUint32(plaintext, uint32(len(messageBytes)))
	copy(plaintext[4:], messageBytes)
	c.prng.Read(plaintext[4+len(messageBytes):])

	var sealed []byte
	if to.ratchet != nil {
		sealed = to.ratchet.Encrypt(sealed, plaintext)
	} else {
		sealedLen := ephemeralBlockLen + nonceLen + len(plaintext) + box.Overhead
		sealed = make([]byte, sealedLen)
		var outerNonce [24]byte
		c.prng.Read(outerNonce[:])
		copy(sealed, outerNonce[:])
		x := sealed[nonceLen:]

		public, private, err := box.GenerateKey(c.prng)
		if err != nil {
			logger.Printf(logger.INFO, "Failed to generate key for outgoing message: %s\n", err)
			return
		}
		box.Seal(x[:0], public[:], &outerNonce, &to.theirCurrentDHPublic, &to.lastDHPrivate)
		x = x[len(public)+box.Overhead:]

		var innerNonce [24]byte
		c.prng.Read(innerNonce[:])
		copy(x, innerNonce[:])
		x = x[nonceLen:]
		box.Seal(x[:0], plaintext, &innerNonce, &to.theirCurrentDHPublic, private)
	}

	sha := sha256.New()
	sha.Write(sealed)
	digest := sha.Sum(nil)
	sha.Reset()
	groupSig, err := to.myGroupKey.Sign(c.prng, digest, sha)
	if err != nil {
		logger.Printf(logger.INFO, "Failed to sign outgoing message: %s\n", err)
		return
	}

	request := &pond.Request{
		Deliver: &pond.Delivery{
			To:             to.theirIdentityPublic[:],
			GroupSignature: groupSig,
			Generation:     proto.Uint32(to.generation),
			Message:        sealed,
		},
	}

	sigReq.resultChan <- request
}
