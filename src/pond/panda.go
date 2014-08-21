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
	panda_proto "github.com/agl/pond/panda/proto"
	pond "github.com/agl/pond/protos"
	"github.com/bfix/gospel/logger"
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
		c.log("Startup key exchange failed with " + err.Error())
		return err
	}

	secret := panda.SharedSecret{
		Secret: sharedSecret,
	}

	mp := c.getNewPanda()

	c.contacts[contact.id] = contact
	kx, err := panda.NewKeyExchange(c.prng, mp, &secret, contact.kxsBytes)
	if err != nil {
		return err
	}
	contact.pandaKeyExchange = kx.Marshal()
	printKeyExchange(contact.pandaKeyExchange)
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
		logger.Printf(logger.INFO, "Performing key exchange...")
		printKeyExchange(kx.Marshal())
		result, err = kx.Run()
	}
	if err == panda.ShutdownErr {
		logger.Printf(logger.INFO, "PANDA shutdown error")
		return
	}
	c.pandaChan <- PandaUpdate{
		id:     id,
		err:    err,
		result: result,
	}
	if err != nil {
		logger.Printf(logger.INFO, "PANDA update failed: %s\n", err.Error())
	} else {
		logger.Println(logger.INFO, "PANDA updated successfully")
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

func printKeyExchange(buf []byte) {
	var p panda_proto.KeyExchange
	if err := proto.Unmarshal(buf, &p); err != nil {
		logger.Println(logger.INFO, "KeyExchange: "+err.Error())
		return
	}
	logger.Println(logger.INFO, "KeyExchange: "+p.String())
}
