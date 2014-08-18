/*
 * Handle user-related data (in persistent repository)
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
	"database/sql"
	"errors"
	"github.com/bfix/gospel/logger"
	"github.com/go-sql-driver/mysql"
)

///////////////////////////////////////////////////////////////////////
/*
 * Initialize user module.
 * @return error - error instance or nil
 */
func InitUserModule() error {
	var err error
	g.db, err = sql.Open("mysql", g.config.Database.Connect)
	return err
}

///////////////////////////////////////////////////////////////////////
// User-related mathods (persistence, key handling,...)

/*
 * Get the public key of a registered mail user.
 * @param toAddr string - mail address of user
 * @return []byte - public key of user (OpenPGP armored ASCII format)
 * @return error - error instance or nil
 */
func GetEmailUserKey(toAddr string) ([]byte, error) {
	var (
		id     int
		ts     mysql.NullTime
		status int
		addr   string
		key    []byte
	)
	rows, err := g.db.Query(g.config.Database.SelectMailUser, toAddr)
	if err != nil {
		logger.Println(logger.ERROR, "Unable to query registered user table (email)")
		return nil, err
	}
	if !rows.Next() {
		logger.Println(logger.WARN, "No registered user '"+toAddr+"'")
		return nil, errors.New("No such user: " + toAddr)
	}
	if err = rows.Scan(&id, &ts, &status, &addr, &key); err != nil {
		logger.Println(logger.ERROR, "Unable to select user record: "+err.Error())
		return nil, err
	}
	return key, nil
}

//---------------------------------------------------------------------
/*
 * Register a (new) mail user: Registration fails if a record with
 * the given mail address already exists in the database or the
 * public key is invalid.
 * @param addr string - mail address of user
 * @param key []byte - public key of user (OpenPGP armored ASCII format)
 * @return error - error instance or nil
 */
func RegisterEmailUser(addr string, key []byte) error {
	var err error = nil
	defer func() {
		if err == nil {
			logger.Println(logger.INFO, "Sending REG-SUCCESS message to '"+addr+"'")
			err = SendEmailRegSuccess(addr)
		} else {
			logger.Println(logger.INFO, "Sending REG-FAILURE message to '"+addr+"'")
			err = SendEmailRegFailure(addr, err.Error())
		}
		if err != nil {
			logger.Println(logger.ERROR, err.Error())
		}
	}()

	el, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(key))
	if err != nil || len(el) != 1 {
		err = errors.New("Invalid public key")
		return err
	}
	pk := el[0].PrimaryKey
	if pk == nil {
		err = errors.New("Invalid public key")
		return err
	}
	rows, err := g.db.Query(g.config.Database.SelectMailUser, addr)
	if err != nil {
		logger.Println(logger.CRITICAL, "Unable to query registered user table (email)")
		err = errors.New("Database error")
		return err
	}
	if !rows.Next() {
		logger.Println(logger.INFO, "Registering user '"+addr+"'")
		_, err = g.db.Exec(g.config.Database.InsertMailUser, addr, key)
		if err != nil {
			logger.Println(logger.CRITICAL, "Unable to insert into user table (email)")
			err = errors.New("Database error")
		}
	} else {
		err = errors.New("User already registered")
	}
	return err
}
