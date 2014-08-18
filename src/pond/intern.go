package pond

import (
	"bytes"
	"code.google.com/p/go.crypto/nacl/box"
	"code.google.com/p/goprotobuf/proto"
	"crypto/sha256"
	"errors"
	"github.com/agl/ed25519"
	"github.com/agl/pond/bbssig"
	"github.com/agl/pond/client/disk"
	pond "github.com/agl/pond/protos"
	"github.com/agl/pond/transport"
	"github.com/bfix/gospel/logger"
	"github.com/bfix/gospel/network"
	"strconv"
	"time"
)

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
}

func (c *Client) transact(server *Server, req *pond.Request, anonymous bool) (*pond.Reply, error) {
	id := c.id
	if anonymous {
		id = NewRandomIdentity()
	}
	rawConn, err := network.Socks5Connect("tcp", server.addr, server.port, c.proxy)
	if err != nil {
		return nil, err
	}
	rawConn.SetDeadline(time.Now().Add(60 * time.Second))
	conn := transport.NewClient(rawConn, &id.secret, &id.public, &c.server.id.public)
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
		id:           randUInt64(),
		receivedTime: time.Now(),
		from:         from.id,
		sealed:       f.Message,
	}

	if !from.isPending {
		if !c.unsealMessage(inboxMsg, from) || len(inboxMsg.message.Body) == 0 {
			return
		}
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

func (c *Client) processServerAnnounce(m NewMessage) {
	inboxMsg := &InboxMessage{
		id:           randUInt64(),
		receivedTime: time.Now(),
		from:         0,
		message:      m.announce.Message,
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
				logger.Printf(logger.WARN, "Failed to parse revocation from %s", to.name)
				return
			}
			to.generation++
			if !to.myGroupKey.Update(bbsRev) {
				to.revokedUs = true
				logger.Printf(logger.INFO, "Revoked by %s", to.name)

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
				to.myGroupKey.Group.Update(bbsRev)
			}
		}
		return
	}

	msg.sent = time.Now()
	if msg.revocation {
		c.deleteOutboxMsg(msg.id)
	}
	c.SaveState(false)
}
