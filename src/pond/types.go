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

const (
	MF_RECEIVED = iota
	MF_SEND
	MF_SEND_FAILED
	MF_ACK
)

type MessageFeedback struct {
	Mode int
	Id   uint64
	Info string
}

type InboxMessage struct {
	Id           uint64
	Read         bool
	ReceivedTime time.Time
	From         uint64
	Sealed       []byte
	Acked        bool
	Message      *pond.Message
	//	cliId cliId
	Retained     bool
	ExposureTime time.Time
	Decryptions  map[uint64]*PendingDecryption
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
