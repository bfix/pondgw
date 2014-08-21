/*
 * Handle SMTP to send and POP3 to receive messages
 *
 * (c) 2013-2014 Bernd Fix    >Y<
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
	"bytes"
	"code.google.com/p/go.crypto/openpgp"
	"code.google.com/p/go.crypto/openpgp/armor"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/bfix/gospel/logger"
	"github.com/bfix/gospel/network"
	"io"
	"io/ioutil"
	mrand "math/rand"
	"mime/multipart"
	"net/mail"
	"net/textproto"
	"os"
	"strings"
	"text/template"
	"time"
)

///////////////////////////////////////////////////////////////////////
// Global constants

const (
	CT_MP_MIX = "multipart/mixed;"
	CT_MP_ENC = "multipart/encrypted;"

	MAIL_CMD_QUIT = iota
)

///////////////////////////////////////////////////////////////////////
// Types

type MailMessage []string

///////////////////////////////////////////////////////////////////////
/*
 * Initialize mail module
 * @return error - error instance or nil
 */
func InitMailModule() error {
	rdr, err := os.Open(g.config.Email.PrivateKey)
	if err != nil {
		return err
	}
	keyring, err := openpgp.ReadArmoredKeyRing(rdr)
	rdr.Close()
	if err != nil {
		return err
	}
	if len(keyring) != 1 {
		return errors.New("Invalid private key")
	}
	g.identity = keyring[0]
	out := new(bytes.Buffer)
	wrt, err := armor.Encode(out, openpgp.PublicKeyType, nil)
	if err != nil {
		return err
	}
	err = g.identity.PrimaryKey.Serialize(wrt)
	wrt.Close()
	if err != nil {
		return err
	}
	g.pubkey = out.Bytes()
	return nil
}

///////////////////////////////////////////////////////////////////////
// Mail-related functions

/*
 * Poll the POP3 server for unread messages. Retrieve messages and
 * and send them to the handler on a specified channel. Transfered
 * messages are deleted on the server.
 * @param ch chan<- MailMessage - channel of message passing
 * @param ctrl <-chan int - channel for instructions
 */
func PollMailServer(ch chan<- MailMessage, ctrl <-chan int) {
	logger.Println(logger.INFO, "Starting POP3 polling loop")

	buf := make([]byte, 8)
	rand.Read(buf)
	seed := int64(binary.LittleEndian.Uint64(buf))
	rnd := mrand.New(mrand.NewSource(seed))
	wait := func(t int) <-chan time.Time {
		if t == 0 {
			t = g.config.Email.Poll
		}
		delay := time.Duration(rnd.ExpFloat64()*float64(t)*1000) * time.Millisecond
		logger.Printf(logger.INFO, "Next POP3 poll in %s seconds\n", delay)
		return time.After(delay)
	}
	heartbeat := wait(5)
	for {
		select {
		case cmd := <-ctrl:
			switch cmd {
			case MAIL_CMD_QUIT:
				break
			}

		case <-heartbeat:
			logger.Println(logger.INFO, "Connecting to server")
			sess, err := network.POP3Connect(g.config.Email.POP3, g.config.Proxy)
			if err != nil {
				logger.Println(logger.ERROR, err.Error())
			}
			logger.Println(logger.INFO, "Listing unread messages")
			idList, err := sess.ListUnread()
			if err != nil {
				logger.Println(logger.ERROR, err.Error())
			}
			logger.Printf(logger.INFO, "%d unread message(s) found\n", len(idList))
			for _, id := range idList {
				msg, err := sess.Retrieve(id)
				if err != nil {
					logger.Println(logger.ERROR, err.Error())
					continue
				}
				ch <- msg
				sess.Delete(id)
			}
			logger.Println(logger.INFO, "Disconnecting from server")
			sess.Close()
			heartbeat = wait(0)
		}
	}
	logger.Println(logger.INFO, "Leaving POP3 polling loop")
}

//---------------------------------------------------------------------
/*
 * Handle incoming message:
 * Email messages must be encrypted (to the gateway public key) and
 * singned by the registered user key. The only message accepted
 * unencrypted and unsigned is an initial registration email.
 * @param msg MailMessage - multi-line message
 * @return error - error instance or nil
 */
func HandleIncomingMailMessage(msg MailMessage) error {
	buf := new(bytes.Buffer)
	for _, s := range msg {
		buf.WriteString(s + "\n")
	}
	m, err := mail.ReadMessage(buf)
	if err != nil {
		return err
	}
	addr, err := mail.ParseAddress(m.Header.Get("From"))
	if err != nil {
		return err
	}

	logger.Println(logger.DBG_HIGH, "Handle incoming message...")
	ct := m.Header.Get("Content-Type")
	if strings.HasPrefix(ct, CT_MP_MIX) {
		var (
			body string
			key  []byte
		)
		boundary := ExtractValue(ct, "boundary")
		rdr := multipart.NewReader(m.Body, boundary)
		for {
			if part, err := rdr.NextPart(); err == nil {
				ct = part.Header.Get("Content-Type")
				logger.Println(logger.DBG, "Content-Type: "+ct)
				switch {
				case strings.HasPrefix(ct, "text/plain;"):
					data, err := ioutil.ReadAll(part)
					if err != nil {
						return err
					}
					body = string(data)
				case strings.HasPrefix(ct, "application/pgp-keys;"):
					key, err = ioutil.ReadAll(part)
					if err != nil {
						return err
					}
				default:
					return errors.New("Unhandled MIME part: " + ct)
				}
			} else if err == io.EOF {
				break
			} else {
				return err
			}
		}
		if strings.HasPrefix(body, "register") {
			return ValidateMailUser(addr.Address, key)
		}
		logger.Printf(logger.INFO, "Dropping unencrypted message from '%s'\n", addr.Address)
	} else if strings.HasPrefix(ct, CT_MP_ENC) {
		logger.Println(logger.DBG, "Content-Type: "+ct)
		boundary := ExtractValue(ct, "boundary")
		logger.Printf(logger.DBG, "Boundary: '%s'\n", boundary)
		rdr := multipart.NewReader(m.Body, boundary)
		var body []byte
		for {
			if part, err := rdr.NextPart(); err == nil {
				ct = part.Header.Get("Content-Type")
				logger.Println(logger.DBG, "Content-Type: "+ct)
				switch {
				case strings.HasPrefix(ct, "application/pgp-encrypted"):
					buf, err := ioutil.ReadAll(part)
					if err != nil {
						return err
					}
					logger.Printf(logger.DBG, "Content: '%s'\n", strings.TrimSpace(string(buf)))
					continue
				case strings.HasPrefix(ct, "application/octet-stream;"):
					rdr, err := armor.Decode(part)
					if err != nil {
						return err
					}
					prompt := func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
						priv := keys[0].PrivateKey
						if priv.Encrypted {
							priv.Decrypt([]byte(g.config.Email.Passphrase))
						}
						buf := new(bytes.Buffer)
						priv.Serialize(buf)
						return buf.Bytes(), nil
					}
					md, err := openpgp.ReadMessage(rdr.Body, openpgp.EntityList{g.identity}, prompt, nil)
					if err != nil {
						return err
					}
					body, err = ioutil.ReadAll(md.UnverifiedBody)
					if err != nil {
						return err
					}
					logger.Printf(logger.DBG, "Body: '%s'\n", body)
					if md.IsSigned {
						data, err := GetMailUserData(addr.Address)
						if err != nil {
							return err
						}
						key, err := GetPublicKey(data.PubKey)
						if err != nil {
							return err
						}
						h := md.Signature.Hash.New()
						if _, err = h.Write(body); err != nil {
							return err
						}
						if err = key.VerifySignature(h, md.Signature); err != nil {
							return err
						}
						logger.Println(logger.DBG, "Signature verified OK")
					} else {
						logger.Printf(logger.INFO, "Dropping unsigned message from '%s'\n", addr.Address)
					}
				default:
					return errors.New("Unhandled MIME part: " + ct)
				}
			} else if err == io.EOF {
				break
			} else {
				return err
			}
		}
	}
	return nil
}

//---------------------------------------------------------------------
/*
 * Extract value from string ('... key="value" ...')
 * @param s string - input string
 * @param key string - name of key
 * @param string - value string (or empty)
 */
func ExtractValue(s, key string) string {
	idx := strings.Index(s, key)
	skip := idx + len(key) + 2
	if idx < 0 || len(s) < skip {
		return ""
	}
	s = s[skip:]
	idx = strings.IndexRune(s, '"')
	if idx < 0 {
		return ""
	}
	return s[:idx]
}

//---------------------------------------------------------------------
/*
 * Send a notification mail to user.
 * @param toAddr string - mail address of user
 * @param key []byte - public key of user (OpenPGP armored ASCII format)
 * @param tplName string - name of template file for email
 * @param data interface{} - template parameters
 * @return error - error instance or nil
 */
func SendNotificationEmail(toAddr string, key []byte, tplName string, data interface{}) error {
	tpl, err := template.ParseFiles(tplName)
	if err != nil {
		return err
	}
	out := new(bytes.Buffer)
	if err = tpl.Execute(out, data); err != nil {
		logger.Println(logger.ERROR, err.Error())
		return err
	}
	att := new(network.MailAttachment)
	att.Header = textproto.MIMEHeader{}
	att.Header.Set("Content-Type", "application/pgp-keys;\n name=\"pubkey.asc\"")
	att.Header.Set("Content-Transfer-Encoding", "7bit")
	att.Header.Set("Content-Disposition", "attachment;\n filename=\"pubkey.asc\"")
	att.Data = g.pubkey
	buf, err := network.CreateMailMessage(out.Bytes(), []*network.MailAttachment{att})
	if err != nil {
		logger.Println(logger.ERROR, err.Error())
		return err
	}
	userData, err := GetMailUserData(toAddr)
	if err != nil {
		logger.Println(logger.ERROR, err.Error())
		return err
	}
	msg, err := network.EncryptMailMessage(userData.PubKey, buf)
	if err != nil {
		logger.Println(logger.ERROR, err.Error())
		return err
	}
	if err = network.SendMailMessage(g.config.Email.SMTP, g.config.Proxy, g.config.Email.Address, toAddr, msg); err != nil {
		logger.Println(logger.ERROR, err.Error())
	}
	return err
}
