/*
Copyright (c) 2013 Adam Langley. All rights reserved.
Modifications: Copyright (c) 2014 Bernd Fix. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name Pond nor the names of its contributors may be
used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
package pond

import (
	"bytes"
	"code.google.com/p/go.crypto/nacl/box"
	"code.google.com/p/goprotobuf/proto"
	"crypto/sha256"
	"encoding/binary"
	pond "github.com/agl/pond/protos"
	"io"
	"time"
)

const (
	nonceLen          = 24
	ephemeralBlockLen = nonceLen + 32 + box.Overhead
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
		c.log("was asked to unseal message from pending contact")
		panic(0)
	}

	sealed := inboxMsg.Sealed
	plaintext, ok := c.decryptMessage(sealed, from)

	if !ok {
		c.log("Failed to decrypt message")
		return false
	}

	if len(plaintext) < 4 {
		c.log("Plaintext too small to process")
		return false
	}

	mLen := int(binary.LittleEndian.Uint32(plaintext[:4]))
	plaintext = plaintext[4:]
	if mLen < 0 || mLen > len(plaintext) {
		c.log("Plaintext length incorrect: %d", mLen)
		return false
	}
	plaintext = plaintext[:mLen]

	msg := new(pond.Message)
	if err := proto.Unmarshal(plaintext, msg); err != nil {
		c.log("Failed to parse message: " + err.Error())
		return false
	}

	for _, candidate := range c.inbox {
		if candidate.From == from.id &&
			candidate.Id != inboxMsg.Id &&
			candidate.Message != nil &&
			*candidate.Message.Id == *msg.Id {
			c.log("Dropping duplicate message from %s", from.name)
			return false
		}
	}

	if from.ratchet == nil {
		if l := len(msg.MyNextDh); l != len(from.theirCurrentDHPublic) {
			c.log("Bad Diffie-Hellman value length: %d", l)
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
				c.MessageFeedbackChan <- MessageFeedback{
					Mode: MF_ACK,
					Id:   candidate.id,
					Info: c.contacts[candidate.to].name,
				}
				break
			}
		}
	}

	if msg.SupportedVersion != nil {
		from.supportedVersion = *msg.SupportedVersion
	}

	from.kxsBytes = nil
	inboxMsg.Message = msg
	inboxMsg.Sealed = nil
	inboxMsg.Read = false

	return true
}

func (c *Client) processSigningRequest(sigReq SigningRequest) {
	defer close(sigReq.resultChan)
	to := c.contacts[sigReq.msg.to]

	messageBytes, err := proto.Marshal(sigReq.msg.message)
	if err != nil {
		c.log("Failed to sign outgoing message: %s", err)
		return
	}
	if len(messageBytes) > pond.MaxSerializedMessage {
		c.log("Failed to sign outgoing message because it's too large")
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
			c.log("Failed to generate key for outgoing message: %s", err)
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
		c.log("Failed to sign outgoing message: %s", err)
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
