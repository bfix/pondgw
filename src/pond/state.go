package pond

import (
	//	"fmt"
	"code.google.com/p/goprotobuf/proto"
	"errors"
	"github.com/agl/pond/bbssig"
	"github.com/agl/pond/client/disk"
	"github.com/agl/pond/client/ratchet"
	"github.com/agl/pond/protos"
	"io"
	"time"
)

const (
	ERASURE_ROTATION_TIME = 24 * time.Hour
	MESSAGE_LIFETIME      = 7 * 24 * time.Hour
	PREVIOUSTAG_LIFETIME  = 14 * 24 * time.Hour
)

func (c *Client) SaveState(rotate bool) error {
	now := time.Now()
	rotateErasureStorage := now.Before(c.lastErasureStorageTime) || now.Sub(c.lastErasureStorageTime) > ERASURE_ROTATION_TIME
	if rotateErasureStorage {
		c.lastErasureStorageTime = now
		// something is missing here?...
	}
	stateBytes, err := proto.Marshal(c.State())
	if err != nil {
		return err
	}
	c.writerChan <- disk.NewState{stateBytes, rotate, false}
	return nil
}

func (c *Client) EraseState() {
	c.writerChan <- disk.NewState{nil, false, true}
	<-c.writerDone
}

func (c *Client) State() *disk.State {
	var err error
	var contacts []*disk.Contact

	for _, contact := range c.contacts {
		cont := &disk.Contact{
			Id:               proto.Uint64(contact.id),
			Name:             proto.String(contact.name),
			GroupKey:         contact.groupKey.Marshal(),
			IsPending:        proto.Bool(contact.isPending),
			KeyExchangeBytes: contact.kxsBytes,
			LastPrivate:      contact.lastDHPrivate[:],
			CurrentPrivate:   contact.currentDHPrivate[:],
			SupportedVersion: proto.Int32(contact.supportedVersion),
			PandaKeyExchange: contact.pandaKeyExchange,
			PandaError:       proto.String(contact.pandaResult),
			RevokedUs:        proto.Bool(contact.revokedUs),
		}
		if !contact.isPending {
			cont.MyGroupKey = contact.myGroupKey.Marshal()
			cont.TheirGroup = contact.myGroupKey.Group.Marshal()
			cont.TheirServer = proto.String(contact.theirServer)
			cont.TheirPub = contact.theirPub[:]
			cont.Generation = proto.Uint32(contact.generation)

			cont.TheirIdentityPublic = contact.theirIdentityPublic[:]
			cont.TheirLastPublic = contact.theirLastDHPublic[:]
			cont.TheirCurrentPublic = contact.theirCurrentDHPublic[:]
		}
		if contact.ratchet != nil {
			cont.Ratchet = contact.ratchet.Marshal(time.Now(), MESSAGE_LIFETIME)
		}
		for _, prevTag := range contact.previousTags {
			if time.Since(prevTag.expired) > PREVIOUSTAG_LIFETIME {
				continue
			}
			cont.PreviousTags = append(cont.PreviousTags, &disk.Contact_PreviousTag{
				Tag:     prevTag.tag,
				Expired: proto.Int64(prevTag.expired.Unix()),
			})
		}
		cont.Events = make([]*disk.Contact_Event, 0, len(contact.events))
		for _, event := range contact.events {
			if time.Since(event.t) > MESSAGE_LIFETIME {
				continue
			}
			cont.Events = append(cont.Events, &disk.Contact_Event{
				Time:    proto.Int64(event.t.Unix()),
				Message: proto.String(event.msg),
			})
		}
		contacts = append(contacts, cont)
	}

	var inbox []*disk.Inbox
	for _, msg := range c.inbox {
		if time.Since(msg.receivedTime) > MESSAGE_LIFETIME && !msg.retained {
			continue
		}
		m := &disk.Inbox{
			Id:           proto.Uint64(msg.id),
			From:         proto.Uint64(msg.from),
			ReceivedTime: proto.Int64(msg.receivedTime.Unix()),
			Acked:        proto.Bool(msg.acked),
			Read:         proto.Bool(msg.read),
			Sealed:       msg.sealed,
			Retained:     proto.Bool(msg.retained),
		}
		if msg.message != nil {
			if m.Message, err = proto.Marshal(msg.message); err != nil {
				panic(err)
			}
		}
		inbox = append(inbox, m)
	}

	var outbox []*disk.Outbox
	for _, msg := range c.outbox {
		if time.Since(msg.created) > MESSAGE_LIFETIME {
			continue
		}
		m := &disk.Outbox{
			Id:         proto.Uint64(msg.id),
			To:         proto.Uint64(msg.to),
			Server:     proto.String(msg.server),
			Created:    proto.Int64(msg.created.Unix()),
			Revocation: proto.Bool(msg.revocation),
		}
		if msg.message != nil {
			if m.Message, err = proto.Marshal(msg.message); err != nil {
				panic(err)
			}
		}
		if !msg.sent.IsZero() {
			m.Sent = proto.Int64(msg.sent.Unix())
		}
		if !msg.acked.IsZero() {
			m.Acked = proto.Int64(msg.acked.Unix())
		}
		if msg.request != nil {
			if m.Request, err = proto.Marshal(msg.request); err != nil {
				panic(err)
			}
		}
		outbox = append(outbox, m)
	}

	var drafts []*disk.Draft
	for _, draft := range c.drafts {
		m := &disk.Draft{
			Id:          proto.Uint64(draft.id),
			Body:        proto.String(draft.body),
			Attachments: draft.attachments,
			Detachments: draft.detachments,
			Created:     proto.Int64(draft.created.Unix()),
		}
		if draft.to != 0 {
			m.To = proto.Uint64(draft.to)
		}
		if draft.inReplyTo != 0 {
			m.InReplyTo = proto.Uint64(draft.inReplyTo)
		}
		drafts = append(drafts, m)
	}

	state := &disk.State{
		Private:                c.private[:],
		Public:                 c.public[:],
		Identity:               c.id.secret[:],
		Server:                 proto.String(c.server.url),
		Group:                  c.groupPrivate.Group.Marshal(),
		GroupPrivate:           c.groupPrivate.Marshal(),
		Generation:             proto.Uint32(c.generation),
		Contacts:               contacts,
		Inbox:                  inbox,
		Outbox:                 outbox,
		Drafts:                 drafts,
		LastErasureStorageTime: proto.Int64(c.lastErasureStorageTime.Unix()),
	}
	for _, prevGroupPriv := range c.prevGroupPrivs {
		if time.Since(prevGroupPriv.expired) > PREVIOUSTAG_LIFETIME {
			continue
		}

		state.PreviousGroupPrivateKeys = append(state.PreviousGroupPrivateKeys, &disk.State_PreviousGroup{
			Group:        prevGroupPriv.priv.Group.Marshal(),
			GroupPrivate: prevGroupPriv.priv.Marshal(),
			Expired:      proto.Int64(prevGroupPriv.expired.Unix()),
		})
	}
	return state
}

func newClientFromState(state *disk.State, prng io.Reader) (*Client, error) {
	var err error
	c := new(Client)
	c.init()
	c.prng = prng
	c.server, err = NewServer(*state.Server)
	if err != nil {
		return nil, err
	}
	c.id, err = NewIdentity(state.Identity)
	if err != nil {
		return nil, err
	}
	group, ok := new(bbssig.Group).Unmarshal(state.Group)
	if !ok {
		return nil, errors.New("client: failed to unmarshal group")
	}
	c.groupPrivate, ok = new(bbssig.PrivateKey).Unmarshal(group, state.GroupPrivate)
	if !ok {
		return nil, errors.New("client: failed to unmarshal group private key")
	}

	if len(state.Private) != len(c.private) {
		return nil, errors.New("client: failed to unmarshal private key")
	}
	copy(c.private[:], state.Private)
	if len(state.Public) != len(c.public) {
		return nil, errors.New("client: failed to unmarshal public key")
	}
	copy(c.public[:], state.Public)
	c.generation = *state.Generation

	if state.LastErasureStorageTime != nil {
		c.lastErasureStorageTime = time.Unix(*state.LastErasureStorageTime, 0)
	}

	for _, prevGroupPriv := range state.PreviousGroupPrivateKeys {
		group, ok := new(bbssig.Group).Unmarshal(prevGroupPriv.Group)
		if !ok {
			return nil, errors.New("client: failed to unmarshal previous group")
		}
		priv, ok := new(bbssig.PrivateKey).Unmarshal(group, prevGroupPriv.GroupPrivate)
		if !ok {
			return nil, errors.New("client: failed to unmarshal previous group private key")
		}
		c.prevGroupPrivs = append(c.prevGroupPrivs, PreviousGroupPrivateKey{
			priv:    priv,
			expired: time.Unix(*prevGroupPriv.Expired, 0),
		})
	}

	for _, cont := range state.Contacts {
		contact := &Contact{
			id:               *cont.Id,
			name:             *cont.Name,
			kxsBytes:         cont.KeyExchangeBytes,
			pandaKeyExchange: cont.PandaKeyExchange,
			pandaResult:      cont.GetPandaError(),
			revokedUs:        cont.GetRevokedUs(),
		}
		c.registerId(contact.id)
		c.contacts[contact.id] = contact
		if contact.groupKey, ok = new(bbssig.MemberKey).Unmarshal(c.groupPrivate.Group, cont.GroupKey); !ok {
			return nil, errors.New("client: failed to unmarshal group member key")
		}
		copy(contact.lastDHPrivate[:], cont.LastPrivate)
		copy(contact.currentDHPrivate[:], cont.CurrentPrivate)
		if cont.Ratchet != nil {
			contact.ratchet = c.newRatchet(contact)
			if err := contact.ratchet.Unmarshal(cont.Ratchet); err != nil {
				return nil, err
			}
		}

		if cont.IsPending != nil && *cont.IsPending {
			contact.isPending = true
			continue
		}

		theirGroup, ok := new(bbssig.Group).Unmarshal(cont.TheirGroup)
		if !ok {
			return nil, errors.New("client: failed to unmarshal their group")
		}
		if contact.myGroupKey, ok = new(bbssig.MemberKey).Unmarshal(theirGroup, cont.MyGroupKey); !ok {
			return nil, errors.New("client: failed to unmarshal my group key")
		}

		if cont.TheirServer == nil {
			return nil, errors.New("client: contact missing server")
		}
		contact.theirServer = *cont.TheirServer

		if len(cont.TheirPub) != len(contact.theirPub) {
			return nil, errors.New("client: contact missing public key")
		}
		copy(contact.theirPub[:], cont.TheirPub)

		if len(cont.TheirIdentityPublic) != len(contact.theirIdentityPublic) {
			return nil, errors.New("client: contact missing identity public key")
		}
		copy(contact.theirIdentityPublic[:], cont.TheirIdentityPublic)

		copy(contact.theirLastDHPublic[:], cont.TheirLastPublic)
		copy(contact.theirCurrentDHPublic[:], cont.TheirCurrentPublic)

		for _, prevTag := range cont.PreviousTags {
			contact.previousTags = append(contact.previousTags, PreviousTag{
				tag:     prevTag.Tag,
				expired: time.Unix(*prevTag.Expired, 0),
			})
		}

		if cont.Generation != nil {
			contact.generation = *cont.Generation
		}
		if cont.SupportedVersion != nil {
			contact.supportedVersion = *cont.SupportedVersion
		}

		contact.events = make([]Event, 0, len(cont.Events))
		for _, evt := range cont.Events {
			event := Event{
				t:   time.Unix(*evt.Time, 0),
				msg: *evt.Message,
			}
			contact.events = append(contact.events, event)
		}
	}

	now := time.Now()
	for _, m := range state.Inbox {
		msg := &InboxMessage{
			id:           *m.Id,
			from:         *m.From,
			receivedTime: time.Unix(*m.ReceivedTime, 0),
			acked:        *m.Acked,
			read:         *m.Read,
			sealed:       m.Sealed,
			retained:     m.GetRetained(),
			exposureTime: now,
		}
		c.registerId(msg.id)
		if len(m.Message) > 0 {
			msg.message = new(protos.Message)
			if err := proto.Unmarshal(m.Message, msg.message); err != nil {
				return nil, errors.New("client: corrupt message in inbox: " + err.Error())
			}
		}
		c.inbox = append(c.inbox, msg)
	}

	for _, m := range state.Outbox {
		msg := &OutboxMessage{
			id:      *m.Id,
			to:      *m.To,
			server:  *m.Server,
			created: time.Unix(*m.Created, 0),
		}
		c.registerId(msg.id)
		if len(m.Message) > 0 {
			msg.message = new(protos.Message)
			if err := proto.Unmarshal(m.Message, msg.message); err != nil {
				return nil, errors.New("client: corrupt message in outbox: " + err.Error())
			}
		}
		if m.Sent != nil {
			msg.sent = time.Unix(*m.Sent, 0)
		}
		if m.Acked != nil {
			msg.acked = time.Unix(*m.Acked, 0)
		}
		if len(m.Request) != 0 {
			msg.request = new(protos.Request)
			if err := proto.Unmarshal(m.Request, msg.request); err != nil {
				return nil, errors.New("client: corrupt request in outbox: " + err.Error())
			}
		}
		msg.revocation = m.GetRevocation()
		if msg.revocation && len(msg.server) == 0 {
			msg.server = c.server.url
		}
		c.outbox = append(c.outbox, msg)
		if msg.sent.IsZero() && (msg.to == 0 || !c.contacts[msg.to].revokedUs) {
			c.Enqueue(msg)
		}
	}

	for _, m := range state.Drafts {
		draft := &Draft{
			id:          *m.Id,
			body:        *m.Body,
			attachments: m.Attachments,
			detachments: m.Detachments,
			created:     time.Unix(*m.Created, 0),
		}
		c.registerId(draft.id)
		if m.To != nil {
			draft.to = *m.To
		}
		if m.InReplyTo != nil {
			draft.inReplyTo = *m.InReplyTo
		}
		c.drafts[draft.id] = draft
	}
	return c, nil
}

func (c *Client) newRatchet(contact *Contact) *ratchet.Ratchet {
	r := ratchet.New(c.prng)
	r.MyIdentityPrivate = &c.id.secret
	r.MySigningPublic = &c.id.public
	r.TheirIdentityPublic = &contact.theirIdentityPublic
	r.TheirSigningPublic = &contact.theirPub
	return r
}

func (c *Client) registerId(id uint64) {
	if c.usedIds[id] {
		panic("duplicate ID registered")
	}
	c.usedIds[id] = true
}
