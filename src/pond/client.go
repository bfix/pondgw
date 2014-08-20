package pond

import (
	"code.google.com/p/go.crypto/curve25519"
	"code.google.com/p/goprotobuf/proto"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/agl/ed25519"
	"github.com/agl/ed25519/extra25519"
	"github.com/agl/pond/bbssig"
	"github.com/agl/pond/client/disk"
	"github.com/agl/pond/panda"
	pond "github.com/agl/pond/protos"
	"github.com/bfix/gospel/logger"
	"io"
	mrand "math/rand"
	"os"
	"sync"
	"time"
)

const (
	transactionRateSeconds = 300
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
		}
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
		c.proxy = proxy
		c.stateFile = stateFile
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
		c = new(Client)
		c.init()
		c.prng = prng
		c.proxy = proxy
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
		_, err = c.transact(c.server, req, false)
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

func (c *Client) GetPublicId() string {
	return hex.EncodeToString(c.id.public[:])
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
		reply, err := c.transact(server, req, useAnonymousIdentity)
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
