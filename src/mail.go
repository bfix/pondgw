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
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/bfix/gospel/crypto"
	"github.com/bfix/gospel/logger"
	"github.com/bfix/gospel/network"
	"golang.org/x/crypto/openpgp"
	"io"
	mrand "math/rand"
	"net/http"
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
	MAIL_CMD_QUIT = iota

	mailChar   = "[a-zA-Z0-9!#$%&'*/=?^_`{|}~-]"
	mailAddrRE = "^" + mailChar + "+(?:\\." + mailChar + "+)*(\\+(?P<sub>" + mailChar + "+)*)?" +
		"@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.?)+(?P<tld>[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)?$"
)

var (
	emailRegexp = regexp.MustCompile(mailAddrRE)
	tlds        = make([]string, 0)
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
	g.pubkey, err = crypto.GetArmoredPublicKey(g.identity)
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
				continue
			}
			logger.Println(logger.INFO, "Listing unread messages")
			idList, err := sess.ListUnread()
			if err != nil {
				logger.Println(logger.ERROR, err.Error())
				logger.Println(logger.INFO, "Disconnecting from server")
				sess.Close()
				continue
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
	getInfo := func(key int, data string) interface{} {
		switch key {
		case network.INFO_SENDER:
			data, err := GetMailUserData(data)
			if err != nil {
				return nil
			}
			keyring, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(data.PubKey))
			if err != nil {
				return nil
			}
			return keyring[0]
		case network.INFO_IDENTITY:
			return g.identity
		case network.INFO_PASSPHRASE:
			return g.config.Email.Passphrase
		}
		return nil
	}
	content, err := network.ParseMailMessage(buf, getInfo)
	if err != nil {
		return err
	}
	body := strings.Split(content.Body, "\n")

	if strings.HasPrefix(body[0], "register") {
		return ValidateMailUser(content.From, content.Key)
	}

	toAddr := ""
	if sub := GetSubAddress(content.To); len(sub) > 0 {
		logger.Printf(logger.INFO, "Received message to sub-address %s\n", sub)
		toAddr = sub
	} else if strings.HasPrefix(body[0], "To:") {
		toAddr = strings.TrimSpace(body[0][3:])
	} else {
		logger.Printf(logger.INFO, "Dropping message '%v'\n", content)
		return nil
	}
	rcpt, err := g.idEngine.GetPeerId(toAddr)
	if err != nil {
		return err
	}
	logger.Printf(logger.INFO, "Forwarding mail message from '%s' to '%s'\n", content.From, rcpt.String())
	outMsg := "From: " + content.From +
		"\nTo: " + content.To +
		"\nSubject: " + content.Subject +
		"\n\n" + content.Body
	return SendPondMessage(rcpt.String(), outMsg)
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
 * Send a mail to user:
 * If the user is registered, the email wll be encrpted to the public
 * key of the recipient.
 * @param toAddr string - mail address of user
 * @param body []byte - mail body
 */
func SendEmailMessage(toAddr string, body []byte) error {
	buf, err := network.CreateMailMessage(body, nil)
	if err != nil {
		logger.Println(logger.ERROR, err.Error())
		return err
	}
	var msg []byte
	userData, err := GetMailUserData(toAddr)
	if err == nil {
		msg, err = network.EncryptMailMessage(userData.PubKey, buf)
		if err != nil {
			logger.Println(logger.ERROR, err.Error())
			msg = buf
		}
	} else {
		msg = buf
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

//---------------------------------------------------------------------
/*
 * Get first sub-address from an email address (if any)
 * @param addr string - email address to be checked
 * @return string - sub-address (or empty)
 */
func GetSubAddress(addr string) string {
	if !emailRegexp.MatchString(addr) {
		return ""
	}
	names := emailRegexp.SubexpNames()
	values := emailRegexp.FindAllStringSubmatch(addr, -1)
	for i, n := range names {
		if n == "sub" {
			return values[0][i]
		}
	}
	return ""
}
