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
	"bufio"
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
	"net/http"
	"net/mail"
	"net/textproto"
	"os"
	"regexp"
	"strings"
	"text/template"
	"time"
)

///////////////////////////////////////////////////////////////////////
// Module-local/global constants and variables.

const (
	ct_MP_MIX = "multipart/mixed;"
	ct_MP_ENC = "multipart/encrypted;"

	mode_PLAIN = iota
	mode_SIGN_ENC

	MAIL_CMD_QUIT = iota

	mailAddrRE = "^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*" +
		"@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.?)+(?P<tld>[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)?$"
)

var (
	emailRegexp = regexp.MustCompile(mailAddrRE)
	tlds        = make([]string, 0)
)

///////////////////////////////////////////////////////////////////////
// Types

type MailMessage []string

//---------------------------------------------------------------------
/*
 * Result type for parsing mail messages
 */
type MailContent struct {
	mode int    // message type (mode_XXX)
	body string // message body
	key  []byte // attached key (register) or signing key (else)
}

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
	g.pubkey, err = GetArmoredPublicKey(g.identity)
	if err != nil {
		return err
	}
	resp, err := http.Get("https://data.iana.org/TLD/tlds-alpha-by-domain.txt")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	list := bufio.NewReader(resp.Body)
	for {
		data, _, err := list.ReadLine()
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		if data[0] == '#' {
			continue
		}
		tlds = append(tlds, string(data))
	}
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
		d := rnd.ExpFloat64() * float64(t) * 1000
		if d < 2000 {
			d *= 100.
		}
		delay := time.Duration(d) * time.Millisecond
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
			heartbeat = wait(g.config.Email.Poll)
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
	var content *MailContent = nil
	if strings.HasPrefix(ct, ct_MP_MIX) {
		content, err = ParsePlain(ct, m.Body)
		if err != nil {
			return err
		}
	} else if strings.HasPrefix(ct, ct_MP_ENC) {
		content, err = ParseSecured(ct, addr.Address, m.Body)
		if err != nil {
			return err
		}
	}
	body := strings.Split(content.body, "\n")
	if content.mode == mode_PLAIN {
		if strings.HasPrefix(body[0], "register") {
			return ValidateMailUser(addr.Address, content.key)
		}
		logger.Printf(logger.INFO, "Dropping unencrypted message from '%s'\n", addr.Address)
	} else if content.mode == mode_SIGN_ENC {
		switch {
		case strings.HasPrefix(body[0], "register"):
			return ValidateMailUser(addr.Address, content.key)
		case strings.HasPrefix(body[0], "To:"):
			rcpt := strings.TrimSpace(body[0][3:])
			logger.Printf(logger.INFO, "Forwarding mail message from '%s' to '%s'\n", addr.Address, rcpt)
			outMsg := "From: " + addr.Address + "\n" + content.body
			return SendPondMessage(rcpt, outMsg)
		}
		logger.Printf(logger.INFO, "Dropping signed/encrypted message from '%s'\n", addr.Address)
	}
	return nil
}

//---------------------------------------------------------------------
/*
 * Parse plain text message.
 * @param ct string - content type string
 * @param body io.Reader - content reader
 * @return *MailContent - parse result
 * @return error - error instance or nil
 */
func ParsePlain(ct string, body io.Reader) (*MailContent, error) {
	mc := new(MailContent)
	mc.mode = mode_PLAIN
	boundary := ExtractValue(ct, "boundary")
	rdr := multipart.NewReader(body, boundary)
	for {
		if part, err := rdr.NextPart(); err == nil {
			ct = part.Header.Get("Content-Type")
			switch {
			case strings.HasPrefix(ct, "text/plain;"):
				data, err := ioutil.ReadAll(part)
				if err != nil {
					return nil, err
				}
				mc.body = string(data)
			case strings.HasPrefix(ct, "application/pgp-keys;"):
				mc.key, err = ioutil.ReadAll(part)
				if err != nil {
					return nil, err
				}
			default:
				return nil, errors.New("Unhandled MIME part: " + ct)
			}
		} else if err == io.EOF {
			break
		} else {
			return nil, err
		}
	}
	return mc, nil
}

//---------------------------------------------------------------------
/*
 * Parse encrypted and signed message.
 * @param ct string - content type string
 * @param addr string - sender address
 * @param body io.Reader - content reader
 * @return *MailContent - parse result
 * @return error - error instance or nil
 */
func ParseSecured(ct, addr string, body io.Reader) (*MailContent, error) {
	mc := new(MailContent)
	mc.mode = mode_SIGN_ENC
	boundary := ExtractValue(ct, "boundary")
	rdr := multipart.NewReader(body, boundary)
	for {
		if part, err := rdr.NextPart(); err == nil {
			ct = part.Header.Get("Content-Type")
			switch {
			case strings.HasPrefix(ct, "application/pgp-encrypted"):
				buf, err := ioutil.ReadAll(part)
				if err != nil {
					return nil, err
				}
				logger.Printf(logger.DBG, "Content: '%s'\n", strings.TrimSpace(string(buf)))
				continue
			case strings.HasPrefix(ct, "application/octet-stream;"):
				rdr, err := armor.Decode(part)
				if err != nil {
					return nil, err
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
					return nil, err
				}
				if md.IsSigned {
					data, err := GetMailUserData(addr)
					if err != nil {
						return nil, err
					}
					keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(data.PubKey))
					if err != nil {
						return nil, err
					}
					md.SignedBy = GetKeyFromIdentity(keyring[0], keySIGN)
					md.SignedByKeyId = md.SignedBy.PublicKey.KeyId
					mc.key, err = GetArmoredPublicKey(keyring[0])
					if err != nil {
						return nil, err
					}
					content, err := ioutil.ReadAll(md.UnverifiedBody)
					if err != nil {
						return nil, err
					}
					if md.SignatureError != nil {
						return nil, md.SignatureError
					}
					logger.Println(logger.INFO, "Signature verified OK")

					m, err := mail.ReadMessage(bytes.NewBuffer(content))
					if err != nil {
						return nil, err
					}
					ct = m.Header.Get("Content-Type")
					mc2, err := ParsePlain(ct, m.Body)
					if err != nil {
						return nil, err
					}
					mc.body = mc2.body
				} else {
					logger.Printf(logger.INFO, "Dropping unsigned message from '%s'\n", addr)
					return nil, nil
				}
			default:
				return nil, errors.New("Unhandled MIME part: " + ct)
			}
		} else if err == io.EOF {
			break
		} else {
			return nil, err
		}
	}
	return mc, nil
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

//---------------------------------------------------------------------
/*
 * Send a mail to user.
 * @param toAddr string - mail address of user
 * @param body []byte - mail body
 */
func SendEmailMessage(toAddr string, body []byte) error {
	buf, err := network.CreateMailMessage(body, nil)
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

//---------------------------------------------------------------------
/*
 * Check if an email is valid.
 * @param addr string - email address to be checked
 * @return bool - is email address valid?
 */
func IsValidEmailAddress(addr string) bool {
	if !emailRegexp.MatchString(addr) {
		return false
	}
	names := emailRegexp.SubexpNames()
	values := emailRegexp.FindAllStringSubmatch(addr, -1)
	tld := ""
	for i, n := range names {
		if n == "tld" {
			tld = strings.ToUpper(values[0][i])
			break
		}
	}
	if len(tld) == 0 {
		return true
	}
	for _, t := range tlds {
		if tld == t {
			return true
		}
	}
	return false
}
