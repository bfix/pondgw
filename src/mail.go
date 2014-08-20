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
	"errors"
	"github.com/bfix/gospel/logger"
	"github.com/bfix/gospel/network"
	"io"
	"io/ioutil"
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
	BOUNDARY_PLAIN = "multipart/mixed; boundary="
	BOUNDARY_ENC   = "multipart/encrypted; boundary="

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
	rdr, err := os.Open(g.prvkey)
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
	wrt, err := armor.Encode(out, "PGP PUBLIC KEY", nil)
	if err != nil {
		return err
	}
	defer wrt.Close()
	if err = g.identity.PrimaryKey.Serialize(wrt); err != nil {
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
	heartbeat := time.NewTicker(g.config.Email.Poll * time.Minute)
	for {
		select {
		case cmd := <-ctrl:
			switch cmd {
			case MAIL_CMD_QUIT:
				break
			}

		case <-heartbeat.C:
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
			logger.Printf(logger.INFO, "%d unread messages found\n", len(idList))
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
		}
	}
	logger.Println(logger.INFO, "Leaving POP3 polling loop")
}

//---------------------------------------------------------------------
/*
 * Handle incoming message.
 * @param msg MailMessage - multi-line message
 * @return error - error instance or nil
 */
func HandleIncomingMailMessage(msg MailMessage) error {
	var (
		body string
		key  []byte
	)
	buf := new(bytes.Buffer)
	for _, s := range msg {
		buf.WriteString(s + "\n")
	}
	m, err := mail.ReadMessage(buf)
	if err != nil {
		return err
	}
	ct := m.Header.Get("Content-Type")
	if strings.HasPrefix(ct, BOUNDARY_PLAIN) {
		boundary := ct[len(BOUNDARY_PLAIN)+1 : len(ct)-1]
		rdr := multipart.NewReader(m.Body, boundary)
		for {
			if part, err := rdr.NextPart(); err == nil {
				ct = part.Header.Get("Content-Type")
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
			user := m.Header.Get("From")
			addr, err := mail.ParseAddress(user)
			if err != nil {
				return err
			}
			if err = RegisterMailUser(addr.Address, key); err != nil {
				return err
			}
		}
	}
	return nil
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
