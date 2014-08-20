package pond

import (
	//	"fmt"
	"github.com/agl/pond/bbssig"
	"github.com/agl/pond/client/ratchet"
	pond "github.com/agl/pond/protos"
	"time"
)

type Server struct {
	id   *PublicIdentity
	addr string
	port int
	url  string
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
}

type PublicIdentity struct {
	public [32]byte
}

type Identity struct {
	PublicIdentity
	secret [32]byte
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
