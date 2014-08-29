/*
 * PeerId/Token scheme:
 * --------------------
 * A PeerId is a 64-bit identifier that is assigned to a Pond identity
 * during registration at the gateway. The Pond user should keep this
 * information private (although there is no security risk itself if
 * the information is known to others except that people can use
 * "unauthorized" email addresses for the Pond identity).
 *
 * 128-bit Tokens are derived from this PeerId; the Token is the
 * AES256-encrypted PeerId concatenated with a 64-bit random value. The
 * encryption key is kept secret and is only known to the gateway, which
 * usesit to generate tokens and to decrypt them to PeerIds.
 *
 * Tokens allow the Pond user to use as many unrelated email identifiers
 * as desired; Pond users are encouraged to give each email contact a
 * different token and thus obfuscating the fact that they all belong
 * to the same Pond identity.
 *
 * Tokens are used by email contacts (either persons or bots/mailing
 * lists) to send messages to a Pond user; the email address of a
 * Pond user looks like "pondgw+<token>@hoi-polloi.org" where "<token>"
 * is the base32-encoded token.
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
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"github.com/bfix/gospel/bitcoin/util"
	"strings"
)

///////////////////////////////////////////////////////////////////////
// Global types

/*
 * IdEngine handles the creation of PeerIds and derived Tokens based
 * on the Paillier encryption scheme.
 */
type IdEngine struct {
	crypt cipher.Block
}

//---------------------------------------------------------------------
/*
 * PeerId represents the base identification of Pond identites.
 */
type PeerId struct {
	data []byte
}

///////////////////////////////////////////////////////////////////////
// Global methods

//---------------------------------------------------------------------
/* Re-instantiate an IdEngine from binary data
 * @param data []byte - binary AES256 key
 * @return *IdEngine - new engine instance
 * @return error - error instance or nil
 */
func NewIdEngine(data []byte) (*IdEngine, error) {
	if len(data) != 32 {
		return nil, errors.New("Invalid AES256 keysize")
	}
	var err error
	e := new(IdEngine)
	e.crypt, err = aes.NewCipher(data)
	if err != nil {
		return nil, err
	}
	return e, nil
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
	res.data, err = randBytes(8)
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
	token, err := randBytes(16)
	if err != nil {
		return "", err
	}
	copy(token, p.data)
	enc := cipher.NewCBCEncrypter(e.crypt, make([]byte, 16))
	enc.CryptBlocks(token, token)
	s := base32.StdEncoding.EncodeToString(token)
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
	token, err := base32.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		return nil, err
	}
	if len(token) != 16 {
		return nil, errors.New("Invalid token length")
	}
	dec := cipher.NewCBCDecrypter(e.crypt, make([]byte, 16))
	dec.CryptBlocks(token, token)
	id := new(PeerId)
	id.data = make([]byte, 8)
	copy(id.data, token)
	return id, nil
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
	return &PeerId{data: buf}, nil
}

//---------------------------------------------------------------------
/*
 * Convert PeerId to base58-encoded representation.
 * @return string - base58-encoded peer identifier
 */
func (p *PeerId) String() string {
	return util.Base58Encode(p.data)
}

//---------------------------------------------------------------------
/*
 * Check if to peer identifiers are equal
 * @param q *PeerId - compare instance to this peer identifier
 * @return bool - are peer identifiers equal?
 */
func (p *PeerId) Equals(q *PeerId) bool {
	return subtle.ConstantTimeCompare(p.data, q.data) == 1
}

//---------------------------------------------------------------------
/*
 * Generate an array of random bytes
 * @param size int - number of bytes requested
 * @return []byte - generated byte array
 * @return error - error instance or nil
 */
func randBytes(size int) ([]byte, error) {
	data := make([]byte, size)
	n, err := g.prng.Read(data)
	if err != nil {
		return nil, err
	}
	if n != size {
		return nil, errors.New("PRNG failure")
	}
	return data, nil
}
