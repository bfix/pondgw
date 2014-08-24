package pond

import (
	"bytes"
	"code.google.com/p/go.crypto/curve25519"
	"code.google.com/p/go.crypto/nacl/box"
	"code.google.com/p/goprotobuf/proto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"github.com/agl/ed25519"
	"github.com/agl/pond/bbssig"
	"github.com/agl/pond/client/disk"
	pond "github.com/agl/pond/protos"
	"github.com/agl/pond/transport"
	"github.com/bfix/gospel/logger"
	"github.com/bfix/gospel/network"
	mrand "math/rand"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func NewServer(host string) (*Server, error) {
	url, err := url.Parse(host)
	if err != nil {
		return nil, err
	}
	if url.Scheme != "pondserver" {
		return nil, errors.New("bad URL scheme, should be pondserver")
	}
	if url.User == nil || len(url.User.Username()) == 0 {
		return nil, errors.New("no server ID in URL")
	}
	server := new(Server)
	server.url = host
	server.id, err = NewPublicIdentityFromBase32(url.User.Username())
	if err != nil {
		return nil, err
	}
	server.addr = url.Host
	if strings.ContainsRune(server.addr, ':') {
		return nil, errors.New("URL contains a port number")
	}
	if !strings.HasSuffix(server.addr, ".onion") {
		return nil, errors.New("host is not a .onion address")
	}
	server.port = 16333
	return server, nil
}

func NewPublicIdentityFromBase32(s string) (*PublicIdentity, error) {
	id := new(PublicIdentity)
	for len(s)%8 != 0 {
		s += "="
	}
	v, err := base32.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(v) != 32 {
		return nil, errors.New("Invalid public identity")
	}
	copy(id.public[:], v)
	return id, nil
}

func NewRandomIdentity() (*Identity, error) {
	secret := randBytes(32)
	id, err := NewIdentity(secret)
	if err != nil {
		return nil, err
	}
	return id, nil
}

func NewIdentity(secret []byte) (*Identity, error) {
	id := new(Identity)
	if len(secret) != len(id.secret) {
		return nil, errors.New("Invalid secret for new identity")
	}
	copy(id.secret[:], secret)
	curve25519.ScalarBaseMult(&id.public, &id.secret)
	return id, nil
}

func (c *Client) init() {
	c.contacts = make(map[uint64]*Contact)
	c.inbox = make([]*InboxMessage, 0)
	c.drafts = make(map[uint64]*Draft)
	c.outbox = make([]*OutboxMessage, 0)
	c.usedIds = make(map[uint64]bool)
	c.queue = make([]*OutboxMessage, 0)
	c.writerChan = make(chan disk.NewState)
	c.writerDone = make(chan struct{})
	c.newMessageChan = make(chan NewMessage)
	c.messageSentChan = make(chan MessageSendResult)
	c.pandaChan = make(chan PandaUpdate, 1)
	c.usedIds = make(map[uint64]bool)
	c.signingRequestChan = make(chan SigningRequest)
}

func (c *Client) transact(server *Server, req *pond.Request, anonymous bool) (*pond.Reply, error) {
	id := c.id
	if anonymous {
		var err error
		if id, err = NewRandomIdentity(); err != nil {
			return nil, err
		}
	}
	rawConn, err := network.Socks5Connect("tcp", server.addr, server.port, c.proxy)
	if err != nil {
		return nil, err
	}
	rawConn.SetDeadline(time.Now().Add(60 * time.Second))
	conn := transport.NewClient(rawConn, &id.secret, &id.public, &server.id.public)
	defer conn.Close()
	if err = conn.Handshake(); err != nil {
		return nil, err
	}
	if err := conn.WriteProto(req); err != nil {
		return nil, err
	}
	reply := new(pond.Reply)
	if err := conn.ReadProto(reply); err != nil {
		return reply, err
	}
	if reply.Status == nil || *reply.Status == pond.Reply_OK {
		return reply, nil
	}
	if msg, ok := pond.Reply_Status_name[int32(*reply.Status)]; ok {
		return reply, errors.New("error from server: " + msg)
	}
	return reply, errors.New("unknown error from server: " + strconv.Itoa(int(*reply.Status)))
}

func (c *Client) indexOfQueuedMessage(msg *OutboxMessage) (index int) {
	for i, queuedMsg := range c.queue {
		if queuedMsg == msg {
			return i
		}
	}
	return -1
}

func (c *Client) enqueue(m *OutboxMessage) {
	c.queueMutex.Lock()
	defer c.queueMutex.Unlock()
	c.queue = append(c.queue, m)
}

func (c *Client) poll() {
	startup := true

	var (
		ackChan chan bool
		head    *OutboxMessage
	)
	lastWasSend := false

	for {
		if head != nil {
			c.queueMutex.Lock()
			head.sending = false
			c.queueMutex.Unlock()
			head = nil
		}

		if !startup {
			if ackChan != nil {
				ackChan <- true
				ackChan = nil
			}

			var timerChan <-chan time.Time
			seed := int64(binary.LittleEndian.Uint64(randBytes(8)))
			r := mrand.New(mrand.NewSource(seed))
			delaySeconds := r.ExpFloat64() * transactionRateSeconds
			delay := time.Duration(delaySeconds*1000) * time.Millisecond
			logger.Printf(logger.INFO, "Next network transaction in %s seconds\n", delay)
			timerChan = time.After(delay)

			select {
			case <-timerChan:
			}
		}
		startup = false

		var (
			req    *pond.Request
			server *Server
			err    error
		)
		useAnonymousIdentity := true
		isFetch := false
		c.queueMutex.Lock()
		if lastWasSend || len(c.queue) == 0 {
			useAnonymousIdentity = false
			isFetch = true
			req = &pond.Request{Fetch: &pond.Fetch{}}
			server = c.server
			logger.Println(logger.INFO, "Starting fetch from home server")
			lastWasSend = false
		} else {
			head = c.queue[0]
			head.sending = true
			c.queue = append(c.queue[1:], head)
			req = head.request
			server, err = NewServer(head.server)
			if err != nil {
				continue
			}
			logger.Printf(logger.INFO, "Starting message transmission to %s\n", server.url)
			if head.revocation {
				useAnonymousIdentity = false
			}
			lastWasSend = true
		}
		c.queueMutex.Unlock()
		c.messageSentChan <- MessageSendResult{}

		if lastWasSend && req == nil {
			resultChan := make(chan *pond.Request, 1)
			c.signingRequestChan <- SigningRequest{head, resultChan}
			req = <-resultChan
			if req == nil {
				continue
			}
		}
		reply, err := c.transact(server, req, useAnonymousIdentity)
		if err != nil {
			logger.Printf(logger.INFO, "Transaction failed: %s\n", err.Error())
			continue
		}
		if !isFetch {
			c.queueMutex.Lock()
			indexOfSentMessage := c.indexOfQueuedMessage(head)
			if indexOfSentMessage == -1 {
				continue
			}
			head.sending = false
			if reply.Status == nil {
				c.removeQueuedMessage(indexOfSentMessage)
				c.queueMutex.Unlock()
				c.messageSentChan <- MessageSendResult{id: head.id}
			} else if *reply.Status == pond.Reply_GENERATION_REVOKED &&
				reply.Revocation != nil {
				c.queueMutex.Unlock()
				c.messageSentChan <- MessageSendResult{id: head.id, revocation: reply.Revocation, extraRevocations: reply.ExtraRevocations}
			} else {
				c.queueMutex.Unlock()
			}

			head = nil
		} else if reply.Fetched != nil || reply.Announce != nil {
			ackChan := make(chan bool)
			c.newMessageChan <- NewMessage{reply.Fetched, reply.Announce, ackChan}
			<-ackChan
		}
	}
}

func (c *Client) removeQueuedMessage(index int) {
	var newQueue []*OutboxMessage
	for i, queuedMsg := range c.queue {
		if i != index {
			newQueue = append(newQueue, queuedMsg)
		}
	}
	c.queue = newQueue
}

func (c *Client) processNewMessage(m NewMessage) {
	defer func() { m.ack <- true }()

	if m.fetched != nil {
		c.processFetch(m)
	} else {
		c.processServerAnnounce(m)
	}
}

func (c *Client) processFetch(m NewMessage) {
	f := m.fetched

	sha := sha256.New()
	sha.Write(f.Message)
	digest := sha.Sum(nil)

	var tag []byte
	var ok bool
	if c.groupPrivate.Verify(digest, sha, f.GroupSignature) {
		tag, ok = c.groupPrivate.Open(f.GroupSignature)
	} else {
		found := false
		for _, prev := range c.prevGroupPrivs {
			if prev.priv.Verify(digest, sha, f.GroupSignature) {
				found = true
				tag, ok = c.groupPrivate.Open(f.GroupSignature)
				break
			}
		}
		if !found {
			logger.Println(logger.ERROR, "Received message with bad group signature!")
			return
		}
	}
	if !ok {
		logger.Println(logger.ERROR, "Failed to open group signature!")
		return
	}

	var from *Contact
NextCandidate:
	for _, candidate := range c.contacts {
		if bytes.Equal(tag, candidate.groupKey.Tag()) {
			from = candidate
			break
		}
		for _, prevTag := range candidate.previousTags {
			if bytes.Equal(tag, prevTag.tag) {
				from = candidate
				break NextCandidate
			}
		}
	}

	if from == nil {
		logger.Printf(logger.ERROR, "Message from unknown contact. Dropping. Tag: %x\n", tag)
		return
	}

	if from.revoked {
		logger.Printf(logger.ERROR, "Message from revoked contact %s. Dropping\n", from.name)
		return
	}

	if len(f.Message) < box.Overhead+24 {
		logger.Println(logger.WARN, "Message too small to process")
		return
	}

	inboxMsg := &InboxMessage{
		Id:           randUInt64(),
		ReceivedTime: time.Now(),
		From:         from.id,
		Sealed:       f.Message,
	}

	if !from.isPending {
		if !c.unsealMessage(inboxMsg, from) || len(inboxMsg.Message.Body) == 0 {
			logger.Printf(logger.INFO, "Can't unseal message from %s. Dropping\n", from.name)
			return
		}
	}

	logger.Printf(logger.INFO, "Adding received messsage %s to inbox.\n", from.name)
	c.MessageFeedbackChan <- MessageFeedback{
		Mode: MF_RECEIVED,
		Id:   inboxMsg.Id,
	}
	c.inbox = append(c.inbox, inboxMsg)
	c.SaveState(false)
}

func (c *Client) deleteOutboxMsg(id uint64) {
	newOutbox := make([]*OutboxMessage, 0, len(c.outbox))
	for _, outboxMsg := range c.outbox {
		if outboxMsg.id == id {
			continue
		}
		newOutbox = append(newOutbox, outboxMsg)
	}
	c.outbox = newOutbox
}

func (c *Client) sendAck(msg *InboxMessage) {
	c.queueMutex.Lock()
	for _, queuedMsg := range c.queue {
		if queuedMsg.sending {
			continue
		}
		if msg.From == queuedMsg.to && !queuedMsg.revocation {
			proto := queuedMsg.message
			proto.AlsoAck = append(proto.AlsoAck, msg.Message.GetId())
			if !tooLarge(queuedMsg) {
				c.queueMutex.Unlock()
				c.log("ACK merged with queued message.")
				return
			}

			proto.AlsoAck = proto.AlsoAck[:len(proto.AlsoAck)-1]
			if len(proto.AlsoAck) == 0 {
				proto.AlsoAck = nil
			}
		}
	}
	c.queueMutex.Unlock()

	to := c.contacts[msg.From]
	var myNextDH []byte
	if to.ratchet == nil {
		var nextDHPub [32]byte
		curve25519.ScalarBaseMult(&nextDHPub, &to.currentDHPrivate)
		myNextDH = nextDHPub[:]
	}

	id := randUInt64()
	err := c.Send(to, &pond.Message{
		Id:               proto.Uint64(id),
		Time:             proto.Int64(time.Now().Unix()),
		Body:             make([]byte, 0),
		BodyEncoding:     pond.Message_RAW.Enum(),
		MyNextDh:         myNextDH,
		InReplyTo:        msg.Message.Id,
		SupportedVersion: proto.Int32(protoVersion),
	})
	if err != nil {
		c.log("Error sending message: %s", err)
	}
}

func tooLarge(msg *OutboxMessage) bool {
	messageBytes, err := proto.Marshal(msg.message)
	if err != nil {
		return true
	}

	return len(messageBytes) > pond.MaxSerializedMessage
}

func (c *Client) processServerAnnounce(m NewMessage) {
	inboxMsg := &InboxMessage{
		Id:           randUInt64(),
		ReceivedTime: time.Now(),
		From:         0,
		Message:      m.announce.Message,
	}

	c.inbox = append(c.inbox, inboxMsg)
	c.SaveState(false)
}

func (c *Client) processMessageSent(msr MessageSendResult) {
	var msg *OutboxMessage
	for _, m := range c.outbox {
		if m.id == msr.id {
			msg = m
			break
		}
	}
	if msg == nil {
		logger.Println(logger.INFO, "Message send result: no assigned message!")
		return
	}

	if msr.revocation != nil {
		to := c.contacts[msg.to]

		for revNum := 0; !to.revokedUs; revNum++ {
			var rev *pond.SignedRevocation
			if revNum == 0 {
				rev = msr.revocation
			} else {
				if n := revNum - 1; n < len(msr.extraRevocations) {
					rev = msr.extraRevocations[n]
				} else {
					break
				}
			}

			if gen := *rev.Revocation.Generation; gen != to.generation {
				logger.Printf(logger.INFO, "Message to '%s' resulted in revocation for generation %d, but current generation is %d\n", to.name, gen, to.generation)
				return
			}

			revBytes, err := proto.Marshal(rev.Revocation)
			if err != nil {
				logger.Printf(logger.WARN, "Failed to marshal revocation message: %s\n", err)
				return
			}

			var sig [ed25519.SignatureSize]byte
			if revSig := rev.Signature; copy(sig[:], revSig) != len(sig) {
				logger.Printf(logger.WARN, "Bad signature length on revocation (%d bytes) from %s\n", len(revSig), to.name)
				return
			}

			var signed []byte
			signed = append(signed, revocationSignaturePrefix...)
			signed = append(signed, revBytes...)
			if !ed25519.Verify(&to.theirPub, signed, &sig) {
				logger.Printf(logger.WARN, "Bad signature on revocation from %s\n", to.name)
				return
			}
			bbsRev, ok := new(bbssig.Revocation).Unmarshal(rev.Revocation.Revocation)
			if !ok {
				logger.Printf(logger.WARN, "Failed to parse revocation from %s\n", to.name)
				return
			}
			to.generation++
			if !to.myGroupKey.Update(bbsRev) {
				to.revokedUs = true
				logger.Printf(logger.INFO, "Revoked by %s\n", to.name)

				newQueue := make([]*OutboxMessage, 0, len(c.queue))
				c.queueMutex.Lock()
				for _, m := range c.queue {
					if m.to != msg.to {
						newQueue = append(newQueue, m)
					}
				}
				c.queue = newQueue
				c.queueMutex.Unlock()
			} else {
				logger.Println(logger.INFO, "Group key updated")
				to.myGroupKey.Group.Update(bbsRev)
			}
		}
		return
	}

	logger.Println(logger.INFO, "Message send result: Success")
	msg.sent = time.Now()
	if msg.revocation {
		c.deleteOutboxMsg(msg.id)
	}
	c.SaveState(false)
}

func randBytes(size int) []byte {
	data := make([]byte, size)
	rand.Read(data)
	return data
}

func randUInt32() uint32 {
	return uint32(randUInt64())
}

func randUInt64() uint64 {
	buf := randBytes(8)
	res, _ := binary.Varint(buf)
	return uint64(res)
}
