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
	"code.google.com/p/goprotobuf/proto"
	"errors"
	"fmt"
	"github.com/agl/ed25519"
	"github.com/agl/ed25519/extra25519"
	"github.com/agl/pond/bbssig"
	"github.com/agl/pond/panda"
	pond "github.com/agl/pond/protos"
)

func (c *Client) StartKeyExchange(peer, sharedSecret string) error {
	if !panda.IsAcceptableSecretString(sharedSecret) {
		c.log("Invalid PANDA shared secret")
		return errors.New("Invalid PANDA shared secret")
	}
	contact := &Contact{
		name:      peer,
		isPending: true,
		id:        randUInt64(),
	}
	if err := c.newKeyExchange(contact); err != nil {
		c.log("Startup key exchange failed with %s", err.Error())
		return err
	}

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
	contact.pandaKeyExchange = kx.Marshal()
	contact.kxsBytes = nil

	c.SaveState(false)
	c.pandaWaitGroup.Add(1)
	contact.pandaShutdownChan = make(chan struct{})
	go c.runPANDA(contact.pandaKeyExchange, contact.id, contact.name, contact.pandaShutdownChan)
	c.log("Key exchange running in background.\n")
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
		Server:         proto.String(c.server.url),
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
	contact.kxsBytes, err = proto.Marshal(kxs)
	return err
}

func (c *Client) runPANDA(serialisedKeyExchange []byte, id uint64, name string, shutdown chan struct{}) {
	var result []byte
	defer c.pandaWaitGroup.Done()

	c.log("Starting PANDA key exchange with %s", name)

	kx, err := panda.UnmarshalKeyExchange(c.prng, c.getNewPanda(), serialisedKeyExchange)
	kx.Testing = false
	kx.Log = func(format string, args ...interface{}) {
		serialised := kx.Marshal()
		c.pandaChan <- PandaUpdate{
			id:         id,
			serialised: serialised,
		}
		c.log("Key exchange with %s: %s", name, fmt.Sprintf(format, args...))
	}
	kx.ShutdownChan = shutdown

	if err == nil {
		c.log("Performing key exchange...")
		result, err = kx.Run()
	}
	if err == panda.ShutdownErr {
		c.log("PANDA shutdown error")
		return
	}
	c.pandaChan <- PandaUpdate{
		id:     id,
		err:    err,
		result: result,
	}
	if err != nil {
		c.log("PANDA update failed: %s", err.Error())
	} else {
		c.log("PANDA updated successfully")
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
		c.log("Key exchange with %s failed: %s", contact.name, update.err)
	case update.serialised != nil:
		if bytes.Equal(contact.pandaKeyExchange, update.serialised) {
			return
		}
		contact.pandaKeyExchange = update.serialised
	case update.result != nil:
		contact.pandaKeyExchange = nil
		contact.pandaShutdownChan = nil

		if err := contact.processKeyExchange(update.result); err != nil {
			contact.pandaResult = err.Error()
			update.err = err
			c.log("Key exchange with %s failed: %s", contact.name, err)
		} else {
			c.log("Key exchange with %s complete", contact.name)
			contact.isPending = false
		}
	}
	c.SaveState(false)
}

func (contact *Contact) processKeyExchange(kxsBytes []byte) error {
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
		v2 := bytes.Equal(curve25519Public[:], kx.IdentityPublic[:])
		if err := contact.ratchet.CompleteKeyExchange(&kx, v2); err != nil {
			return err
		}
	}

	contact.generation = *kx.Generation

	return nil
}
