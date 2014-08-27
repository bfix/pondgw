/*
 * PeerId/Token scheme:
 * --------------------
 * A PeerId is a 64-bit identifier that is assigned to a Pond identity
 * during registration at the gateway. The Pond user should keep this
 * information private.
 *
 * 256-bit Tokens are derived from this PeerId; the Token is the
 * Paillier-encrypted PeerId. Both keys (private and public Paillier
 * keys) are kept secret and are only known to the gateway, which uses
 * them to generate tokens and to decrypt them to PeerIds.
 *
 * The Paillier encryption yields different Tokens each time a PeerId
 * is encrypted; it therefore allows the Pond user to use the Tokens
 * as unrelated email-related identifiers (by giving each email contact
 * a different token) and thus obfuscating the fact that they all beong
 * to the same Pond identity.
 *
 * Tokens are used by email contacts (either persons or bots/mailing
 * lists) to send messages to a Pond user; the email address of a
 * Pond user looks like "pondgw+<token>@hoi-polloi.org" where "<token>"
 * is the base32-encoded token.
 *
 * The key length of the Paillier scheme is only 128 bits (so the
 * public key MUST be kept secret!) so that the resulting to token
 * string is small enough to fit into the local part of an email
 * address (which is limited to 64 characters in total).
 *
 * (c) 2014 Bernd Fix   >Y<
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package main

///////////////////////////////////////////////////////////////////////
// Import external declarations.

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"github.com/bfix/gospel/bitcoin/util"
	"github.com/bfix/gospel/crypto"
	"math/big"
	"strings"
)

///////////////////////////////////////////////////////////////////////
// Package-local constants and variables

const (
	bitLength = 128 // length of Paillier key
)

var (
	maxPeerId = new(big.Int).Lsh(big.NewInt(1), 64)
)

///////////////////////////////////////////////////////////////////////
// Global types

/*
 * IdEngine handles the creation of PeerIds and derived Tokens based
 * on the Paillier encryption scheme.
 */
type IdEngine struct {
	PrivKey *crypto.PaillierPrivateKey
}

//---------------------------------------------------------------------
/*
 * PeerId represents the base identification of Pond identites.
 */
type PeerId struct {
	id *big.Int
}

///////////////////////////////////////////////////////////////////////
// Global methods

/*
 * Instantiate new engine.
 * @return *IdEngine - new engine instance
 * @return error - error instance or nil
 */
func NewIdEngine() (*IdEngine, error) {
	var err error
	e := new(IdEngine)
	e.PrivKey, err = crypto.NewPaillierPrivateKey(bitLength)
	if err != nil {
		return nil, err
	}
	return e, nil
}

//---------------------------------------------------------------------
/* Re-instantiate an IdEngine from binary data
 * @param data []byte - binary representation of an IdEngine
 * @return *IdEngine - new engine instance
 * @return error - error instance or nil
 */
func RestoreIdEngine(data []byte) (*IdEngine, error) {
	e := new(IdEngine)
	if err := json.Unmarshal(data, e); err != nil {
		return nil, err
	}
	return e, nil
}

//---------------------------------------------------------------------
/*
 * Serialize IdEngine instance to binary data
 * @return []byte - binary representation of an IdEngine
 * @return error - error instance or nil
 */
func (e *IdEngine) Serialize() ([]byte, error) {
	data, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return data, nil
}

//---------------------------------------------------------------------
/*
 * Generate a new PeerId for a Pond identity.
 * @return *PeerId - new peer identifier
 * @return error - error instance or nil
 */
func (e *IdEngine) NewPeerId() (*PeerId, error) {
	res := new(PeerId)
	var err error
	res.id, err = rand.Int(rand.Reader, maxPeerId)
	if err != nil {
		return nil, err
	}
	return res, nil
}

//---------------------------------------------------------------------
/*
 * Generate a new token from a peer identifier.
 * @param p *PeerId - peer identifier
 * @return string - generated token (base32-encoded, trimmed)
 * @return error - error instance or nil
 */
func (e *IdEngine) NewToken(p *PeerId) (string, error) {
	token, err := e.PrivKey.GetPublicKey().Encrypt(p.id)
	if err != nil {
		return "", err
	}
	s := base32.StdEncoding.EncodeToString(token.Bytes())
	return strings.Trim(s, "="), nil
}

//---------------------------------------------------------------------
/*
 * Get a PeerId from base32-encoded token.
 * @param tokenStr string - base32 encoded token (trimmed)
 * @return *PeerId - recreated peer identifier
 * @return error - error instance or nil
 */
func (e *IdEngine) GetPeerId(tokenStr string) (*PeerId, error) {
	for len(tokenStr)%8 != 0 {
		tokenStr += "="
	}
	buf, err := base32.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		return nil, err
	}
	token := new(big.Int).SetBytes(buf)
	val, err := e.PrivKey.Decrypt(token)
	if err != nil {
		return nil, err
	}
	return &PeerId{id: val}, nil
}

//---------------------------------------------------------------------
/*
 * Restore a PeerId from base58-encoded representation.
 * @param idStr string - base58 encoded peer identifier
 * @return *PeerId - re-created peer identifier
 * @return error - error instance or nil
 */
func RestorePeerId(idStr string) (*PeerId, error) {
	buf, err := util.Base58Decode(idStr)
	if err != nil {
		return nil, err
	}
	if len(buf) != 8 {
		return nil, errors.New("Invalid peer id string")
	}
	return &PeerId{id: new(big.Int).SetBytes(buf)}, nil
}

//---------------------------------------------------------------------
/*
 * Convert PeerId to base58-encoded representation.
 * @return string - base58-encoded peer identifier
 */
func (p *PeerId) String() string {
	return util.Base58Encode(p.id.Bytes())
}

//---------------------------------------------------------------------
/*
 * Check if to peer identifiers are equal
 * @param q *PeerId - compare instance to this peer identifier
 * @return bool - are peer identifiers equal?
 */
func (p *PeerId) Equals(q *PeerId) bool {
	return p.id.Cmp(q.id) == 0
}
