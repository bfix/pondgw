/*
 * Unit test to check if the designe peer id/token scheme works.
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
	"encoding/json"
	"fmt"
	"github.com/bfix/gospel/bitcoin/util"
	"testing"
)

///////////////////////////////////////////////////////////////////////
// Unit test functions

/*
 * Test if peer id/token scheme really works. :)
 */
func TestPeerIdScheme(t *testing.T) {

	// generate new Paillier key pair
	e, err := NewIdEngine()
	if err != nil {
		t.Fatal(err)
	}

	data, err := e.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("IdEngine: " + util.Base58Encode(data))

	pubKey, err := json.Marshal(e.PrivKey.GetPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("PubKey: " + string(pubKey))

	// instantiate id engine
	e, err = RestoreIdEngine(data)
	if err != nil {
		t.Fatal(err)
	}

	// create base peer identifier
	peerId, err := e.NewPeerId()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Peer identifier: " + peerId.String())

	for i := 0; i < 10; i++ {
		// generate public token
		token, err := e.NewToken(peerId)
		if err != nil {
			t.Fatal(err)
		}

		// reconstruct peer id from token
		id, err := e.GetPeerId(token)
		if err != nil {
			t.Fatal(err)
		}

		// check...
		fmt.Printf("Token #%d: %s --> %s\n", i, token, id.String())
		if !peerId.Equals(id) {
			t.Fatal("Identifiers don't match!!")
		}
	}
}
