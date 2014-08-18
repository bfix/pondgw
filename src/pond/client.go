package pond

import (
	"bytes"
	"code.google.com/p/go.crypto/curve25519"
	"code.google.com/p/go.crypto/nacl/box"
	"code.google.com/p/goprotobuf/proto"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/agl/ed25519"
	"github.com/agl/ed25519/extra25519"
	"github.com/agl/pond/bbssig"
	"github.com/agl/pond/client/disk"
	"github.com/agl/pond/panda"
	pond "github.com/agl/pond/protos"
	"github.com/agl/pond/transport"
	"github.com/bfix/gospel/logger"
	"github.com/bfix/gospel/network"
	"io"
	mrand "math/rand"
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	nonceLen               = 24
	ephemeralBlockLen      = nonceLen + 32 + box.Overhead
	transactionRateSeconds = 300
)

var revocationSignaturePrefix = []byte("revocation\x00")

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
	messageSentChan        chan MessageSendResult
	prng                   io.Reader
	proxy                  string
	log                    Logger
}

func GetClient(stateFileName, stateFilePW string, home, proxy string, prng io.Reader, log Logger) (*Client, error) {
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
			log("Waiting for locked state file")
			for {
				if stateLock, err = stateFile.Lock(false); stateLock != nil {
					break
				}
				time.Sleep(1 * time.Second)
			}
		} else {
			log("Trying to read Pond state file")
			state, err := stateFile.Read(stateFilePW)
			if err != nil {
				log("Reading of Pond state file failed")
				return nil, err
			}
			log("Instanciating Pond client from state file")
			c, err = newClientFromState(state, prng)
			if err != nil {
				log("Pond client creation failed")
				return nil, err
			}
			c.log = log
			c.stateFile = stateFile
		}
	} else {
		if !os.IsNotExist(err) {
			log("Lock creation failed: " + err.Error())
			return nil, err
		}

		log("Instanciating new Pond client")
		pub, priv, err := ed25519.GenerateKey(prng)
		if err != nil {
			return nil, err
		}
		c := new(Client)
		c.init()
		c.prng = prng
		c.id = NewRandomIdentity()
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
		_, err = c.transact(req, false)
		if err != nil {
			return nil, err
		}
		c.log = log
		if err != nil {
			log("Pond client creation failed: " + err.Error())
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
			log("Pond client persistence failed: " + err.Error())
		}
	}
	c.getNewPanda = func() panda.MeetingPlace {
		return &panda.HTTPMeetingPlace{
			TorAddress: proxy,
			URL:        "https://panda-key-exchange.appspot.com/exchange",
		}
	}
	log("Pond client initialization done - starting client")
	return c, nil
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
}

func (c *Client) Run() {
	go c.Poll()

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
	c.log("--> %d PANDA key exchange(s) started.\n", num)

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

func (c *Client) transact(req *pond.Request, anonymous bool) (*pond.Reply, error) {
	id := c.id
	if anonymous {
		id = NewRandomIdentity()
	}
	rawConn, err := network.Socks5Connect("tcp", c.server.addr, c.server.port, c.proxy)
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

func (c *Client) Enqueue(m *OutboxMessage) {
	c.queueMutex.Lock()
	defer c.queueMutex.Unlock()
	c.queue = append(c.queue, m)
}

func (c *Client) Poll() {
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
				logger.Printf(logger.INFO, "Starting fetch")
			}
		}
		startup = false

		var (
			req    *pond.Request
			server string
		)
		useAnonymousIdentity := true
		isFetch := false
		c.queueMutex.Lock()
		if lastWasSend || len(c.queue) == 0 {
			useAnonymousIdentity = false
			isFetch = true
			req = &pond.Request{Fetch: &pond.Fetch{}}
			server = c.server.addr
			logger.Println(logger.INFO, "Starting fetch from home server")
			lastWasSend = false
		} else {
			head = c.queue[0]
			head.sending = true
			c.queue = append(c.queue[1:], head)
			req = head.request
			server = head.server
			logger.Printf(logger.INFO, "Starting message transmission to %s\n", server)
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
		reply, err := c.transact(req, useAnonymousIdentity)
		if err != nil {
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

func (c *Client) startKeyExchange(name, sharedSecret string) error {
	if !panda.IsAcceptableSecretString(sharedSecret) {
		return errors.New("Invalid PANDA shared secret")
	}
	contact := &Contact{
		name:      name,
		isPending: true,
		id:        randUInt64(),
	}
	c.newKeyExchange(contact)

	stack := &panda.CardStack{
		NumDecks: 1,
	}
	secret := panda.SharedSecret{
		Secret: sharedSecret,
		Cards:  *stack,
	}

	mp := c.getNewPanda()

	c.contacts[contact.id] = contact
	kx, err := panda.NewKeyExchange(c.prng, mp, &secret, contact.kxsBytes)
	if err != nil {
		return err
	}
	kx.Testing = false
	contact.pandaKeyExchange = kx.Marshal()
	contact.kxsBytes = nil

	c.SaveState(false)
	c.pandaWaitGroup.Add(1)
	contact.pandaShutdownChan = make(chan struct{})
	go c.runPANDA(contact.pandaKeyExchange, contact.id, contact.name, contact.pandaShutdownChan)
	logger.Println(logger.INFO, "Key exchange running in background.")
	return nil
}

func (c *Client) newKeyExchange(contact *Contact) error {
	var err error
	if contact.groupKey, err = c.groupPrivate.NewMember(c.prng); err != nil {
		return err
	}
	contact.ratchet = c.newRatchet(contact)

	kx := &pond.KeyExchange{
		PublicKey:      c.public[:],
		IdentityPublic: c.id.public[:],
		Server:         proto.String(c.server.addr),
		Group:          contact.groupKey.Group.Marshal(),
		GroupKey:       contact.groupKey.Marshal(),
		Generation:     proto.Uint32(c.generation),
	}
	contact.ratchet.FillKeyExchange(kx)
	kxBytes, err := proto.Marshal(kx)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(&c.private, kxBytes)
	kxs := &pond.SignedKeyExchange{
		Signed:    kxBytes,
		Signature: sig[:],
	}
	if contact.kxsBytes, err = proto.Marshal(kxs); err != nil {
		return err
	}
	return nil
}

func (c *Client) runPANDA(serialisedKeyExchange []byte, id uint64, name string, shutdown chan struct{}) {
	var result []byte
	defer c.pandaWaitGroup.Done()

	logger.Println(logger.INFO, "Starting PANDA key exchange with "+name)

	kx, err := panda.UnmarshalKeyExchange(c.prng, c.getNewPanda(), serialisedKeyExchange)
	kx.Testing = false
	kx.Log = func(format string, args ...interface{}) {
		serialised := kx.Marshal()
		c.pandaChan <- PandaUpdate{
			id:         id,
			serialised: serialised,
		}
		logger.Printf(logger.INFO, "Key exchange with %s: %s", name, fmt.Sprintf(format, args...))
	}
	kx.ShutdownChan = shutdown

	if err == nil {
		result, err = kx.Run()
	}
	if err == panda.ShutdownErr {
		return
	}
	c.pandaChan <- PandaUpdate{
		id:     id,
		err:    err,
		result: result,
	}
}

func (c *Client) processPANDAUpdate(update PandaUpdate) {
	contact, ok := c.contacts[update.id]
	if !ok {
		return
	}
	switch {
	case update.err != nil:
		contact.pandaResult = update.err.Error()
		contact.pandaKeyExchange = nil
		contact.pandaShutdownChan = nil
		logger.Printf(logger.WARN, "Key exchange with %s failed: %s\n", contact.name, update.err)
	case update.serialised != nil:
		if bytes.Equal(contact.pandaKeyExchange, update.serialised) {
			return
		}
		contact.pandaKeyExchange = update.serialised
	case update.result != nil:
		contact.pandaKeyExchange = nil
		contact.pandaShutdownChan = nil

		if err := contact.processKeyExchange(update.result, false, false, false); err != nil {
			contact.pandaResult = err.Error()
			update.err = err
			logger.Printf(logger.WARN, "Key exchange with %s failed: %s\n", contact.name, err)
		} else {
			logger.Printf(logger.INFO, "Key exchange with %s complete\n", contact.name)
			contact.isPending = false
		}
	}
	c.SaveState(false)
}

func (contact *Contact) processKeyExchange(kxsBytes []byte, testing, simulateOldClient, disableV2Ratchet bool) error {
	var kxs pond.SignedKeyExchange
	if err := proto.Unmarshal(kxsBytes, &kxs); err != nil {
		return err
	}

	var sig [64]byte
	if len(kxs.Signature) != len(sig) {
		return errors.New("invalid signature length")
	}
	copy(sig[:], kxs.Signature)

	var kx pond.KeyExchange
	if err := proto.Unmarshal(kxs.Signed, &kx); err != nil {
		return err
	}

	if len(kx.PublicKey) != len(contact.theirPub) {
		return errors.New("invalid public key")
	}
	copy(contact.theirPub[:], kx.PublicKey)

	if !ed25519.Verify(&contact.theirPub, kxs.Signed, &sig) {
		return errors.New("invalid signature")
	}

	contact.theirServer = *kx.Server
	if _, err := NewServer(contact.theirServer); err != nil {
		return err
	}

	group, ok := new(bbssig.Group).Unmarshal(kx.Group)
	if !ok {
		return errors.New("invalid group")
	}
	if contact.myGroupKey, ok = new(bbssig.MemberKey).Unmarshal(group, kx.GroupKey); !ok {
		return errors.New("invalid group key")
	}

	if len(kx.IdentityPublic) != len(contact.theirIdentityPublic) {
		return errors.New("invalid public identity")
	}
	copy(contact.theirIdentityPublic[:], kx.IdentityPublic)

	if simulateOldClient {
		kx.Dh1 = nil
	}

	if len(kx.Dh1) == 0 {
		// They are using an old-style ratchet. We have to extract the
		// private value from the Ratchet in order to use it with the
		// old code.
		contact.lastDHPrivate = contact.ratchet.GetKXPrivateForTransition()
		if len(kx.Dh) != len(contact.theirCurrentDHPublic) {
			return errors.New("invalid public DH value")
		}
		copy(contact.theirCurrentDHPublic[:], kx.Dh)
		contact.ratchet = nil
	} else {
		// If the identity and ed25519 public keys are the same (modulo
		// isomorphism) then the contact is using the v2 ratchet.
		var ed25519Public, curve25519Public [32]byte
		copy(ed25519Public[:], kx.PublicKey)
		extra25519.PublicKeyToCurve25519(&curve25519Public, &ed25519Public)
		v2 := !disableV2Ratchet && bytes.Equal(curve25519Public[:], kx.IdentityPublic[:])
		if err := contact.ratchet.CompleteKeyExchange(&kx, v2); err != nil {
			return err
		}
	}

	contact.generation = *kx.Generation

	return nil
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
