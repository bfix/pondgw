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
	"code.google.com/p/goprotobuf/proto"
	"encoding/hex"
	"errors"
	"github.com/agl/ed25519"
	"github.com/agl/ed25519/extra25519"
	"github.com/agl/pond/bbssig"
	"github.com/agl/pond/client/disk"
	"github.com/agl/pond/panda"
	pond "github.com/agl/pond/protos"
	"golang.org/x/crypto/curve25519"
	"io"
	"os"
	"sync"
	"time"
)

const (
	transactionRateSeconds = 300
	protoVersion           = 1
)

type Logger func(format string, args ...interface{})

type Client struct {
	id                     *Identity
	generation             uint32
	groupPrivate           *bbssig.PrivateKey
	prevGroupPrivs         []PreviousGroupPrivateKey
	private                [64]byte
	public                 [32]byte
	server                 *Server
	contacts               map[uint64]*Contact
	inbox                  []*InboxMessage
	drafts                 map[uint64]*Draft
	outbox                 []*OutboxMessage
	writerChan             chan disk.NewState
	writerDone             chan struct{}
	fetchNowChan           chan chan bool
	stateLock              *disk.Lock
	stateFile              *disk.StateFile
	lastErasureStorageTime time.Time
	usedIds                map[uint64]bool
	queue                  []*OutboxMessage
	queueMutex             sync.Mutex
	pandaChan              chan PandaUpdate
	pandaWaitGroup         sync.WaitGroup
	getNewPanda            func() panda.MeetingPlace
	signingRequestChan     chan SigningRequest
	newMessageChan         chan NewMessage
	MessageFeedbackChan    chan MessageFeedback
	messageSentChan        chan MessageSendResult
	prng                   io.Reader
	proxy                  string
	log                    Logger
}

func GetClient(
	stateFileName, stateFilePW string,
	home, proxy, pandaAddr string,
	prng io.Reader, mfc chan MessageFeedback, log Logger) (*Client, error) {

	var c *Client
	stateFile := &disk.StateFile{
		Path: stateFileName,
		Rand: prng,
		Log:  log,
	}
	newAccount := false
	stateLock, err := stateFile.Lock(false)
	if err == nil {
		if stateLock == nil {
			log("Waiting for locked state file...")
			for {
				if stateLock, err = stateFile.Lock(false); stateLock != nil {
					break
				}
				time.Sleep(1 * time.Second)
			}
		}
		log("Trying to read Pond state file...")
		state, err := stateFile.Read(stateFilePW)
		if err != nil {
			log("Reading of Pond state file failed!")
			return nil, err
		}
		log("Instanciating Pond client from state file")
		c, err = newClientFromState(state, prng, mfc, log)
		if err != nil {
			log("Pond client creation failed")
			return nil, err
		}
		c.log = log
		c.proxy = proxy
		c.stateFile = stateFile
	} else {
		if !os.IsNotExist(err) {
			log("Lock creation failed: %s", err.Error())
			return nil, err
		}

		log("Instanciating new Pond client")
		pub, priv, err := ed25519.GenerateKey(prng)
		if err != nil {
			return nil, err
		}
		c = new(Client)
		c.init()
		c.prng = prng
		c.proxy = proxy
		c.MessageFeedbackChan = mfc
		c.id, err = NewRandomIdentity()
		if err != nil {
			return nil, err
		}
		copy(c.private[:], priv[:])
		copy(c.public[:], pub[:])
		extra25519.PrivateKeyToCurve25519(&c.id.secret, priv)
		curve25519.ScalarBaseMult(&c.id.public, &c.id.secret)

		c.groupPrivate, err = bbssig.GenerateGroup(c.prng)
		if err != nil {
			return nil, err
		}
		c.server, err = NewServer(home)
		if err != nil {
			return nil, err
		}
		c.generation = randUInt32()
		req := new(pond.Request)
		req.NewAccount = &pond.NewAccount{
			Generation: proto.Uint32(c.generation),
			Group:      c.groupPrivate.Group.Marshal(),
		}
		_, err = c.transact(c.server, req, false)
		if err != nil {
			return nil, err
		}
		c.log = log
		if err != nil {
			log("Pond client creation failed: %s", err.Error())
			return nil, err
		}
		newAccount = true
		c.stateLock, err = stateFile.Lock(true)
		if err != nil {
			err = errors.New("Failed to create state file: " + err.Error())
		} else if c.stateLock == nil {
			err = errors.New("Failed to obtain lock on created state file")
		}
		if err != nil {
			return nil, err
		}
		c.lastErasureStorageTime = time.Now()
		c.stateFile = stateFile
		stateFile.Create(stateFilePW)
	}

	log("Starting state handler")
	go c.stateFile.StartWriter(c.writerChan, c.writerDone)

	if newAccount {
		log("Saving state of new Pond client")
		if err = c.SaveState(false); err != nil {
			log("Pond client persistence failed: %s", err.Error())
		}
	}
	c.getNewPanda = func() panda.MeetingPlace {
		return &panda.HTTPMeetingPlace{
			TorAddress: proxy[len("socks5://"):],
			URL:        pandaAddr,
		}
	}
	log("Pond client initialization done - starting client")
	return c, nil
}

func (c *Client) Run() {
	go c.poll()

	c.log("Starting pending PANDA key exchanges:")
	num := 0
	for _, contact := range c.contacts {
		if len(contact.pandaKeyExchange) == 0 {
			continue
		}
		num++
		c.pandaWaitGroup.Add(1)
		contact.pandaShutdownChan = make(chan struct{})
		go c.runPANDA(contact.pandaKeyExchange, contact.id, contact.name, contact.pandaShutdownChan)
	}
	c.log("--> %d PANDA key exchange(s) started.", num)

	for {
		select {
		case sigReq := <-c.signingRequestChan:
			c.processSigningRequest(sigReq)
		case newMessage := <-c.newMessageChan:
			c.processNewMessage(newMessage)
		case msr := <-c.messageSentChan:
			if msr.id != 0 {
				c.processMessageSent(msr)
			}
		case update := <-c.pandaChan:
			c.processPANDAUpdate(update)
		}
	}
}

func (c *Client) Shutdown() {
	c.SaveState(false)
}

func (c *Client) GetInboxMessage(id uint64) *InboxMessage {
	for _, m := range c.inbox {
		if m.Id == id {
			return m
		}
	}
	return nil
}

func (c *Client) DeleteInboxMessage(id uint64) {
	newInbox := make([]*InboxMessage, 0, len(c.inbox))
	for _, inboxMsg := range c.inbox {
		if inboxMsg.Id == id {
			continue
		}
		newInbox = append(newInbox, inboxMsg)
	}
	c.inbox = newInbox
}

func (c *Client) AckMessage(id uint64) {
	for _, m := range c.inbox {
		if m.Id == id {
			m.Acked = true
			c.sendAck(m)
		}
	}
}

func (c *Client) GetPublicId() string {
	return hex.EncodeToString(c.id.public[:])
}

func (c *Client) SendMessage(rcpt, body string) error {

	var to *Contact = nil
	for _, contact := range c.contacts {
		if contact.name == rcpt {
			to = contact
			break
		}
	}
	if to == nil {
		return errors.New("No matching contact found")
	}

	message := &pond.Message{
		Id:               proto.Uint64(randUInt64()),
		Time:             proto.Int64(time.Now().Unix()),
		Body:             []byte(body),
		BodyEncoding:     pond.Message_RAW.Enum(),
		Files:            make([]*pond.Message_Attachment, 0),
		DetachedFiles:    make([]*pond.Message_Detachment, 0),
		SupportedVersion: proto.Int32(protoVersion),
	}

	if to.ratchet == nil {
		var nextDHPub [32]byte
		curve25519.ScalarBaseMult(&nextDHPub, &to.currentDHPrivate)
		message.MyNextDh = nextDHPub[:]
	}

	return c.Send(to, message)
}

func (c *Client) Send(to *Contact, message *pond.Message) error {

	messageBytes, err := proto.Marshal(message)
	if err != nil {
		return err
	}

	if len(messageBytes) > pond.MaxSerializedMessage {
		return errors.New("message too large")
	}

	out := &OutboxMessage{
		id:      *message.Id,
		to:      to.id,
		server:  to.theirServer,
		message: message,
		created: time.Unix(*message.Time, 0),
	}
	c.enqueue(out)
	c.outbox = append(c.outbox, out)

	return nil
}

func (c *Client) GetContact(name string) *Contact {
	for _, contact := range c.contacts {
		if contact.name == name {
			return contact
		}
	}
	return nil
}

func (c *Client) GetContacts() []string {
	list := make([]string, 0)
	for _, contact := range c.contacts {
		list = append(list, contact.name)
	}
	return list
}

func (c *Client) DeleteContact(contact *Contact) {
	var newInbox []*InboxMessage
	for _, msg := range c.inbox {
		if msg.From == contact.id {
			continue
		}
		newInbox = append(newInbox, msg)
	}
	c.inbox = newInbox

	for _, draft := range c.drafts {
		if draft.to == contact.id {
			draft.to = 0
		}
	}

	c.queueMutex.Lock()
	var newQueue []*OutboxMessage
	for _, msg := range c.queue {
		if msg.to == contact.id && !msg.revocation {
			continue
		}
		newQueue = append(newQueue, msg)
	}
	c.queue = newQueue
	c.queueMutex.Unlock()

	var newOutbox []*OutboxMessage
	for _, msg := range c.outbox {
		if msg.to == contact.id && !msg.revocation {
			continue
		}
		newOutbox = append(newOutbox, msg)
	}
	c.outbox = newOutbox

	c.Revoke(contact)

	if contact.pandaShutdownChan != nil {
		close(contact.pandaShutdownChan)
	}

	delete(c.contacts, contact.id)
}

func (c *Client) Revoke(to *Contact) *OutboxMessage {
	to.revoked = true
	revocation := c.groupPrivate.GenerateRevocation(to.groupKey)
	now := time.Now()

	groupCopy, _ := new(bbssig.Group).Unmarshal(c.groupPrivate.Group.Marshal())
	groupPrivCopy, _ := new(bbssig.PrivateKey).Unmarshal(groupCopy, c.groupPrivate.Marshal())
	c.prevGroupPrivs = append(c.prevGroupPrivs, PreviousGroupPrivateKey{
		priv:    groupPrivCopy,
		expired: now,
	})

	for _, contact := range c.contacts {
		if contact == to {
			continue
		}
		contact.previousTags = append(contact.previousTags, PreviousTag{
			tag:     contact.groupKey.Tag(),
			expired: now,
		})
		contact.groupKey.Update(revocation)
	}

	rev := &pond.SignedRevocation_Revocation{
		Revocation: revocation.Marshal(),
		Generation: proto.Uint32(c.generation),
	}

	c.groupPrivate.Group.Update(revocation)
	c.generation++

	revBytes, err := proto.Marshal(rev)
	if err != nil {
		panic(err)
	}

	var signed []byte
	signed = append(signed, revocationSignaturePrefix...)
	signed = append(signed, revBytes...)

	sig := ed25519.Sign(&c.private, signed)

	signedRev := pond.SignedRevocation{
		Revocation: rev,
		Signature:  sig[:],
	}

	request := &pond.Request{
		Revocation: &signedRev,
	}

	out := &OutboxMessage{
		revocation: true,
		request:    request,
		id:         randUInt64(),
		server:     c.server.url, // revocations always go to the home server.
		created:    time.Now(),
	}
	c.enqueue(out)
	c.outbox = append(c.outbox, out)
	return out
}
