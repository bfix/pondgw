package pond

import (
	//	"fmt"
	"code.google.com/p/go.crypto/curve25519"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"github.com/agl/pond/bbssig"
	"github.com/agl/pond/client/ratchet"
	pond "github.com/agl/pond/protos"
	"net/url"
	"strings"
	"time"
)

type Server struct {
	id   *PublicIdentity
	addr string
	port int
	url  string
}

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

type PublicIdentity struct {
	public [32]byte
}

func NewPublicIdentityFromBase32(s string) (*PublicIdentity, error) {
	id := new(PublicIdentity)
	for len(s)%8 != 0 {
		s += "="
	}
	v, err := base32.StdEncoding.DecodeString(s)
	if err == nil {
		if len(v) != 32 {
			return nil, errors.New("Invalid public identity")
		}
		copy(id.public[:], v)
		return id, nil
	}
	return nil, err
}

type Identity struct {
	PublicIdentity
	secret [32]byte
}

func NewRandomIdentity() *Identity {
	var secret [32]byte
	copy(secret[:], randBytes(32))
	id, _ := NewIdentity(secret[:])
	return id
}

func NewIdentity(secret []byte) (*Identity, error) {
	id := new(Identity)
	if len(secret) != len(id.secret) {
		return nil, errors.New("Invalid secret for new identity")
	}
	copy(id.secret[:], secret[:])
	curve25519.ScalarBaseMult(&id.public, &id.secret)
	return id, nil
}

type Draft struct {
	id                 uint64
	created            time.Time
	to                 uint64
	body               string
	inReplyTo          uint64
	attachments        []*pond.Message_Attachment
	detachments        []*pond.Message_Detachment
	pendingDetachments map[uint64]*PendingDetachment
}

type PendingDetachment struct {
	size   int64
	path   string
	cancel func()
}

type Contact struct {
	id                   uint64
	name                 string
	isPending            bool
	kxsBytes             []byte
	groupKey, myGroupKey *bbssig.MemberKey
	previousTags         []PreviousTag
	generation           uint32
	theirServer          string
	theirPub             [32]byte
	theirIdentityPublic  [32]byte
	supportedVersion     int32
	revoked              bool
	revokedUs            bool
	pandaKeyExchange     []byte
	pandaShutdownChan    chan struct{}
	pandaResult          string
	events               []Event
	lastDHPrivate        [32]byte
	currentDHPrivate     [32]byte
	theirLastDHPublic    [32]byte
	theirCurrentDHPublic [32]byte
	ratchet              *ratchet.Ratchet
	//	cliId cliId
}

type InboxMessage struct {
	id           uint64
	read         bool
	receivedTime time.Time
	from         uint64
	sealed       []byte
	acked        bool
	message      *pond.Message
	//	cliId cliId
	retained     bool
	exposureTime time.Time
	decryptions  map[uint64]*PendingDecryption
}

type OutboxMessage struct {
	request    *pond.Request
	id         uint64
	to         uint64
	server     string
	created    time.Time
	sent       time.Time
	acked      time.Time
	revocation bool
	message    *pond.Message
	sending    bool
	//	cliId cliId
}

type PendingDecryption struct {
	index  int
	cancel func()
}

type PreviousGroupPrivateKey struct {
	priv    *bbssig.PrivateKey
	expired time.Time
}

type PreviousTag struct {
	tag     []byte
	expired time.Time
}

type Event struct {
	t   time.Time
	msg string
}

type SigningRequest struct {
	msg        *OutboxMessage
	resultChan chan *pond.Request
}

type PandaUpdate struct {
	id         uint64
	err        error
	result     []byte
	serialised []byte
}

type NewMessage struct {
	fetched  *pond.Fetched
	announce *pond.ServerAnnounce
	ack      chan bool
}

type MessageSendResult struct {
	id               uint64
	revocation       *pond.SignedRevocation
	extraRevocations []*pond.SignedRevocation
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
