/*
 * Pond client interface.
 *
 * (c) 2013-2014 Bernd Fix   >Y<
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
	"github.com/bfix/gospel/logger"
)

///////////////////////////////////////////////////////////////////////
/*
 * Initialize Pond client and start handler loops.
 * @return error - error instance or nil if successful
 */
func InitPondModule() error {

	log := func(format string, args ...interface{}) {
		logger.Printf(logger.INFO, format, args...)
	}
	var err error
	logger.Println(logger.INFO, "Getting Pond client instance")
	g.client, err = pond.GetClient(
		g.config.Pond.StateFile, g.config.Pond.StatePW,
		g.config.Pond.Home, g.config.Proxy,
		g.prng, log)
	if err != nil {
		return err
	}
	logger.Println(logger.INFO, "Starting Pond client")
	go g.client.Run()
	return nil
}
