/*
 * Generate new tokens for given peer identifier
 * =============================================
 * The peer identifier (as issued by the gateway) MUST be specified as
 * an option argument on the command line:
 *
 * $ ./tokenizer -i <peer-id>
 *
 * To build the tokenizer application with a ready-to-go GO installation:
 *
 * $ go build tokenizer.go
 *
 * Experienced users can add their own peer identifier as the default
 * value for the global variable 'peerId' (see line 66). 
 *
 * (c) 2014 Bernd Fix    >Y<
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at
 * your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

package main

///////////////////////////////////////////////////////////////////////
// Import external declarations.

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/bfix/gospel/bitcoin/util"
	"github.com/bfix/gospel/crypto"
	"log"
	"math/big"
)

///////////////////////////////////////////////////////////////////////
// Package-local constants and variables

const (
	pubKeyJSON = "{" +
		"\"N\":{{.N}}," +
		"\"G\":{{.G}}" +
		"}"
)

var (
	peerId string
)

///////////////////////////////////////////////////////////////////////
/*
 * Initialize parameters from command-line options
 */
func init() {
	flag.StringVar(&peerId, "i", "", "peer identifier")
	flag.Parse()
}

//---------------------------------------------------------------------
/*
 * Application entry point
 */
func main() {
	if len(peerId) == 0 {
		flag.Usage()
		return
	}
	id, err := util.Base58Decode(peerId)
	if err != nil {
		log.Fatal(err)
	}
	pubKey := new(crypto.PaillierPublicKey)
	if err = json.Unmarshal([]byte(pubKeyJSON), pubKey); err != nil {
		log.Fatal(err)
	}

	v := new(big.Int).SetBytes(id)
	w, err := pubKey.Encrypt(v)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("New token: " + util.Base58Encode(w.Bytes()))
}
