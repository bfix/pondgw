/*
 * Pond client interface.
 *
 * (c) 2013-2015 Bernd Fix   >Y<
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
	"./pond"
	"bytes"
	"fmt"
	"github.com/bfix/gospel/logger"
	"strings"
)

///////////////////////////////////////////////////////////////////////
/*
 * Initialize Pond client and start handler loops.
 * @return error - error instance or nil if successful
 */
func InitPondModule() error {

	log := func(format string, args ...interface{}) {
		msg := fmt.Sprintf(format, args...)
		logger.Println(logger.INFO, msg)
	}
	mfc := make(chan pond.MessageFeedback)
	go HandleMessageNotifications(mfc)

	var err error
	logger.Println(logger.INFO, "Getting Pond client instance")
	g.client, err = pond.GetClient(
		g.config.Pond.StateFile, g.config.Pond.StatePW,
		g.config.Pond.Home, g.config.Proxy, g.config.Pond.Panda,
		g.prng, mfc, log)
	if err != nil {
		return err
	}
	logger.Println(logger.INFO, "Starting Pond client")
	go g.client.Run()
	return nil
}

//---------------------------------------------------------------------
/*
 * Handle message notifications from client
 * @param mfc <-chan pond.MessageFeedback - incoming notifications
 */
func HandleMessageNotifications(mfc <-chan pond.MessageFeedback) {
	for {
		select {
		case n := <-mfc:
			switch n.Mode {
			case pond.MF_RECEIVED:
				msg := g.client.GetInboxMessage(n.Id)
				if msg == nil {
					logger.Println(logger.WARN, "Unknown inbox message?!")
					continue
				}
				if !msg.Acked {
					body := strings.Split(string(msg.Message.Body), "\n")
					if strings.HasPrefix(body[0], "To:") {
						outMsg := msg.Message.Body
						rcpt := strings.TrimSpace(body[0][3:])
						logger.Printf(logger.INFO, "Forwarding message from '%s' to '%s'\n", n.Info, rcpt)
						if !strings.HasPrefix(body[1], "From:") {
							id, err := RestorePeerId(n.Info)
							if err != nil {
								logger.Printf(logger.WARN, "Invalid peer id '%s' trying to send message.\n", n.Info)
								continue
							}
							tk, err := g.idEngine.NewToken(id)
							if err != nil {
								logger.Printf(logger.WARN, "Failed to generate transient email address: %s\n", err.Error())
								continue
							}
							addr := strings.Split(g.config.Email.Address, "@")
							outMsg = append([]byte("From: "+addr[0]+"+"+tk+"@"+addr[1]+"\n"), outMsg...)
						}
						if err := SendEmailMessage(rcpt, outMsg); err != nil {
							logger.Printf(logger.WARN, "Failed to forward message to '%s'\n", rcpt)
						}
					} else if strings.TrimSpace(body[0]) == "gen-tokens" {
						buf := new(bytes.Buffer)
						id, err := RestorePeerId(n.Info)
						if err != nil {
							logger.Printf(logger.WARN, "Invalid peer id '%s' requested tokens.\n", n.Info)
							continue
						}
						for i := 0; i < 10; i++ {
							tk, err := g.idEngine.NewToken(id)
							if err != nil {
								buf.WriteString(err.Error() + "\n")
							} else {
								buf.WriteString(tk + "\n")
							}
						}
						if err = SendPondMessage(n.Info, string(buf.Bytes())); err != nil {
							logger.Printf(logger.WARN, "Failed to send new tokens to '%s'.\n", n.Info)
						}
					} else {
						logger.Printf(logger.WARN, "Skipping message from '%s'\n", n.Info)
					}
					g.client.AckMessage(n.Id)
				}
				g.client.DeleteInboxMessage(n.Id)
				g.client.SaveState(false)
			case pond.MF_ACK:
				logger.Printf(logger.INFO, "Message acknowledged by %s\n", n.Info)
			}
		}
	}
}

//---------------------------------------------------------------------
/*
 * Send a message to a Pond peer.
 * @param rcpt string - recipient identifier
 * @param body string - message body
 * @return error - error instance or nil if successful
 */
func SendPondMessage(rcpt, body string) error {
	_, err := GetPondUserData(rcpt)
	if err != nil {
		return err
	}
	return g.client.SendMessage(rcpt, body)
}
