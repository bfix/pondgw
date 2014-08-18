/*
 * The control server instance provides a telnet interface for the
 * administration of the Pond/Email gateway service.
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
	"bufio"
	"github.com/bfix/gospel/logger"
	"net"
	"strings"
)

///////////////////////////////////////////////////////////////////////
// Control service instance

type ControlSrv struct {
	Ch chan<- bool // channel to invoker
}

///////////////////////////////////////////////////////////////////////
// ControlService methods (implements Service interface)

/*
 * Handle client connection.
 * @param client net.Conn - connection to client
 */
func (c *ControlSrv) Process(client net.Conn) {

	b := bufio.NewReadWriter(bufio.NewReader(client), bufio.NewWriter(client))
	for repeat := true; repeat; {

		// show control menu
		b.WriteString("\n-----------------------------------\n")
		b.WriteString("Change (L)og level [" + logger.GetLogLevel() + "]\n")
		b.WriteString("(T)erminate application\n")
		b.WriteString("e(X)it\n")
		b.WriteString("-----------------------------------\n")
		b.WriteString("Enter command: ")
		b.Flush()

		// get command input
		cmd, err := readCmd(b)
		if err != nil {
			break
		}

		// handle command
		logger.Println(logger.INFO, "[ctrl] command '"+cmd+"'")
		switch cmd {
		//-------------------------------------------------
		// Terminate application
		//-------------------------------------------------
		case "T":
			b.WriteString("Are you sure? Enter YES to continue: ")
			b.Flush()
			cmd, _ = readCmd(b)
			if cmd == "YES" {
				logger.Println(logger.WARN, "[ctrl] Terminating application")
				b.WriteString("Terminating application...")
				b.Flush()
				c.Ch <- true
			} else {
				logger.Println(logger.WARN, "[ctrl] Response '"+cmd+"' -- Termination aborted!")
				b.WriteString("Wrong response -- Termination aborted!")
				b.Flush()
			}

		//-------------------------------------------------
		// Change logging level
		//-------------------------------------------------
		case "L":
			b.WriteString("Enter new log level (CRITICAL,SEVERE,ERROR,WARN,INFO,DBG_HIGH,DBG,DBG_ALL): ")
			b.Flush()
			cmd, _ = readCmd(b)
			logger.SetLogLevelFromName(cmd)

		//-------------------------------------------------
		//	Quit control session
		//-------------------------------------------------
		case "X":
			repeat = false

		//-------------------------------------------------
		//	Unknown command
		//-------------------------------------------------
		default:
			b.WriteString("Unkonwn command '" + cmd + "'\n")
		}
	}
	client.Close()
}

//---------------------------------------------------------------------
/*
 * Check for TCP protocol.
 * @param protocol string - connection protocol
 * @return bool - protcol handled?
 */
func (c *ControlSrv) CanHandle(protocol string) bool {
	rc := strings.HasPrefix(protocol, "tcp")
	if !rc {
		logger.Println(logger.WARN, "[ctrl] Unsupported protocol '"+protocol+"'")
	}
	return rc
}

//---------------------------------------------------------------------
/*
 * Check for local connection.
 * @param add string - remote address
 * @return bool - local address?
 */
func (c *ControlSrv) IsAllowed(addr string) bool {
	idx := strings.Index(addr, ":")
	ip := addr[:idx]
	if strings.Index(g.config.Control.Allowed, ip) == -1 {
		logger.Println(logger.WARN, "[ctrl] Unsupported remote address '"+addr+"'")
		return false
	}
	return true
}

//---------------------------------------------------------------------
/*
 * Get service name.
 * @return string - name of control service (for logging purposes)
 */
func (c *ControlSrv) GetName() string {
	return "ctrl"
}

///////////////////////////////////////////////////////////////////////
// Private helper methods

/*
 * Read command/input from connection.
 * @param b *bufioReadWriter - reader
 * @return cmd string - read input
 * @return err error - error state
 */
func readCmd(b *bufio.ReadWriter) (cmd string, err error) {
	line, err := b.ReadBytes('\n')
	if err != nil {
		return "", err
	}
	// get rid of enclosing white spaces
	return strings.Trim(string(line), " \t\n\v\r"), nil
}
