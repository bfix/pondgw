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
	"database/sql"
	"encoding/hex"
	"errors"
	"github.com/bfix/gospel/crypto"
	"github.com/bfix/gospel/logger"
	"github.com/go-sql-driver/mysql"
	"time"
)

///////////////////////////////////////////////////////////////////////
// Module-global constants and variables

const (
	statUNKNOWN = iota
	statPENDING
	statREGISTERED
	statACTIVE
	statREVOKED
)

var (
	errDatabase          = errors.New("Database error")
	errNoSuchUser        = errors.New("No such user")
	errAlreadyRegistered = errors.New("User already registered")
	errInvalidPubKey     = errors.New("Invalid public key")
	errPrng              = errors.New("crypto/rand failed")
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
// EMAIL user handling

/*
 * Record of mail user in persistent repository.
 */
type MailUserData struct {
	Id        int
	Timestamp time.Time
	Status    int
	Address   string
	PubKey    []byte // public key of user (OpenPGP armored ASCII format)
	Token     string
}

//---------------------------------------------------------------------
/*
 * Get the data record for a registered mail user.
 * @param toAddr string - mail address of user
 * @return *MailUserData - mail user data record
 * @return error - error instance or nil
 */
func GetMailUserData(toAddr string) (*MailUserData, error) {
	rows, err := g.db.Query(g.config.Database.SelectMailUser, toAddr)
	if err != nil {
		logger.Println(logger.ERROR, "Unable to query registered user table (email)")
		return nil, err
	}
	if !rows.Next() {
		logger.Println(logger.INFO, "No registered user '"+toAddr+"'")
		return nil, errNoSuchUser
	}
	data := new(MailUserData)
	var ts mysql.NullTime
	if err = rows.Scan(&data.Id, &ts, &data.Status, &data.Address, &data.PubKey, &data.Token); err != nil {
		logger.Println(logger.ERROR, "Unable to select user record: "+err.Error())
		return nil, err
	}
	if ts.Valid {
		data.Timestamp = ts.Time
	} else {
		logger.Printf(logger.ERROR, "Invalid timestamp value for mail record: %d\n", data.Id)
		return nil, err
	}
	return data, nil
}

//---------------------------------------------------------------------
/*
 * Get the data record for a registered mail user by token
 * @param token string - confirmation token
 * @return *MailUserData - mail user data record
 * @return error - error instance or nil
 */
func GetMailUserDataByToken(token string) (*MailUserData, error) {
	rows, err := g.db.Query(g.config.Database.SelectMailToken, token)
	if err != nil {
		logger.Println(logger.ERROR, "Unable to query registered user table (email)")
		return nil, err
	}
	if !rows.Next() {
		logger.Println(logger.WARN, "No registered user for token '"+token+"'")
		return nil, errNoSuchUser
	}
	data := new(MailUserData)
	var ts mysql.NullTime
	if err = rows.Scan(&data.Id, &ts, &data.Status, &data.Address, &data.PubKey, &data.Token); err != nil {
		logger.Println(logger.ERROR, "Unable to select user record: "+err.Error())
		return nil, err
	}
	if ts.Valid {
		data.Timestamp = ts.Time
	} else {
		logger.Printf(logger.ERROR, "Invalid timestamp value for mail record: %d\n", data.Id)
		return nil, err
	}
	return data, nil
}

//---------------------------------------------------------------------
/*
 * Insert user data (address, public key and status) into the database.
 * @param toAddr string - mail address of user
 * @param key []byte - public key of user (OpenPGP armored ASCII format)
 * @param status int - status of the user
 * @return error - error instance or nil
 */
func InsertMailUserData(toAddr string, key []byte, status int) (int, string, error) {
	_, err := crypto.GetPublicKey(key)
	if err != nil {
		return 0, "", errInvalidPubKey
	}
	rows, err := g.db.Query(g.config.Database.SelectMailUser, toAddr)
	if err != nil {
		logger.Println(logger.CRITICAL, "Unable to query registered user table (email)")
		return 0, "", errDatabase
	}
	var (
		id    int64
		token string
	)
	if !rows.Next() {
		logger.Println(logger.INFO, "Adding user '"+toAddr+"'")
		buf := make([]byte, 16)
		n, err := g.prng.Read(buf)
		if err != nil || n != 16 {
			logger.Println(logger.CRITICAL, "Unable to generate token")
			return 0, "", errPrng
		}
		token = hex.EncodeToString(buf)
		res, err := g.db.Exec(g.config.Database.InsertMailUser, toAddr, key, status, token)
		if err != nil {
			logger.Println(logger.CRITICAL, "Unable to insert into user table (email)")
			return 0, "", errDatabase
		}
		id, err = res.LastInsertId()
		if err != nil {
			logger.Println(logger.CRITICAL, "Unable to get last inserted id from user table (email)")
			return 0, "", errDatabase
		}
	} else {
		return 0, "", errAlreadyRegistered
	}
	return int(id), token, nil
}

//---------------------------------------------------------------------
/*
 * Update user status in the database.
 * @param toAddr string - mail address of user
 * @param status int - status of the user
 * @return error - error instance or nil
 */
func UpdateMailUserStatus(toAddr string, status int) error {
	logger.Printf(logger.INFO, "Updating status of user '%s' to %d\n", toAddr, status)
	_, err := g.db.Exec(g.config.Database.UpdateMailStatus, toAddr, status)
	if err != nil {
		logger.Println(logger.CRITICAL, "Unable to update user table (email)")
		return errDatabase
	}
	return nil
}

//---------------------------------------------------------------------
/*
 * Drop token for email user in database
 * @param toAddr string - mail address of user
 * @return error - error instance or nil
 */
func DropMailUserToken(toAddr string) error {
	logger.Printf(logger.INFO, "Dropping token for user '%s'\n", toAddr)
	_, err := g.db.Exec(g.config.Database.DropMailToken, toAddr)
	if err != nil {
		logger.Println(logger.CRITICAL, "Unable to update user table (email)")
		return errDatabase
	}
	return nil
}

//---------------------------------------------------------------------
/*
 * Drop email user in database
 * @param toAddr string - mail address of user
 * @return error - error instance or nil
 */
func DropMailUser(toAddr string) error {
	logger.Printf(logger.INFO, "Dropping user '%s'\n", toAddr)
	_, err := g.db.Exec(g.config.Database.DropMailUser, toAddr)
	if err != nil {
		logger.Println(logger.CRITICAL, "Unable to remove from user table (email)")
		return errDatabase
	}
	return nil
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
func RegisterMailUser(addr string, key []byte) error {
	_, _, err := InsertMailUserData(addr, key, statREGISTERED)
	if err == nil {
		logger.Println(logger.INFO, "Sending REG-SUCCESS message to '"+addr+"'")
		param := struct {
			Addr string
		}{
			Addr: g.config.Email.Address,
		}
		err = SendNotificationEmail(addr, key, g.config.Tpls.MailRegSuccess, &param)
	} else {
		logger.Println(logger.INFO, "Sending REG-FAILURE message to '"+addr+"'")
		param := struct {
			Addr string
			Msg  string
			Key  string
			User string
		}{
			Addr: g.config.Email.Address,
			Msg:  err.Error(),
			Key:  string(key),
			User: addr,
		}
		err = SendNotificationEmail(addr, key, g.config.Tpls.MailRegFailure, &param)
	}
	if err != nil {
		logger.Println(logger.ERROR, err.Error())
	}
	return err
}

//---------------------------------------------------------------------
/*
 * Send a validation email to a user that has registered using the
 * web interface.
 * @param addr string - mail address of user
 * @param key []byte - public key of user (OpenPGP armored ASCII format)
 * @return error - error instance or nil
 */
func ValidateMailUser(addr string, key []byte) error {
	_, token, err := InsertMailUserData(addr, key, statPENDING)
	if err == nil {
		logger.Println(logger.INFO, "Sending PENDING-SUCCESS message to '"+addr+"'")
		param := struct {
			Addr    string
			Confirm string
		}{
			Addr:    g.config.Email.Address,
			Confirm: g.config.Web.Host + "/confirm/" + token,
		}
		if err = SendNotificationEmail(addr, key, g.config.Tpls.ValidateMail, &param); err != nil {
			logger.Println(logger.INFO, "Failed to send message-- dropping user '"+addr+"'")
			err = DropMailUser(addr)
		}
	}
	return err
}

///////////////////////////////////////////////////////////////////////
// POND user handling

/*
 * Record of Pond user in persistent repository.
 */
type PondUserData struct {
	Id        int
	Timestamp time.Time
	Status    int
	Peer      string
}

//---------------------------------------------------------------------
/*
 * Get the data record for a registered Pond user
 * @param peer string - peer identification
 * @return *PondUserData - pond user data record
 * @return error - error instance or nil
 */
func GetPondUserData(peer string) (*PondUserData, error) {
	rows, err := g.db.Query(g.config.Database.SelectPondUser, peer)
	if err != nil {
		logger.Println(logger.ERROR, "Unable to query registered user table (pond)")
		return nil, err
	}
	if !rows.Next() {
		logger.Println(logger.WARN, "No registered user '"+peer+"'")
		return nil, errNoSuchUser
	}
	data := new(PondUserData)
	var ts mysql.NullTime
	if err = rows.Scan(&data.Id, &ts, &data.Status, &data.Peer); err != nil {
		logger.Println(logger.ERROR, "Unable to select user record: "+err.Error())
		return nil, err
	}
	if ts.Valid {
		data.Timestamp = ts.Time
	} else {
		logger.Printf(logger.ERROR, "Invalid timestamp value for pond record: %d\n", data.Id)
		return nil, err
	}
	return data, nil
}

//---------------------------------------------------------------------
/*
 * Insert user data (peer id and status) into the database.
 * @param peer string - peer id of Pond user
 * @param status int - status of the user
 * @return error - error instance or nil
 */
func InsertPondUserData(peer string, status int) (int, error) {
	rows, err := g.db.Query(g.config.Database.SelectPondUser, peer)
	if err != nil {
		logger.Println(logger.CRITICAL, "Unable to query registered user table (pond)")
		return 0, errDatabase
	}
	var (
		id int64
	)
	if !rows.Next() {
		logger.Println(logger.INFO, "Adding user '"+peer+"'")
		res, err := g.db.Exec(g.config.Database.InsertPondUser, peer, status)
		if err != nil {
			logger.Println(logger.CRITICAL, "Unable to insert into user table (pond)")
			return 0, errDatabase
		}
		id, err = res.LastInsertId()
		if err != nil {
			logger.Println(logger.CRITICAL, "Unable to get last inserted id from user table (pond)")
			return 0, errDatabase
		}
	} else {
		return 0, errAlreadyRegistered
	}
	return int(id), nil
}

//---------------------------------------------------------------------
/*
 * Update user status in the database.
 * @param peer string - peer id of Pond user
 * @param status int - status of the user
 * @return error - error instance or nil
 */
func UpdatePondUserStatus(peer string, status int) error {
	logger.Printf(logger.INFO, "Updating status of user '%s' to %d\n", peer, status)
	_, err := g.db.Exec(g.config.Database.UpdatePondStatus, peer, status)
	if err != nil {
		logger.Println(logger.CRITICAL, "Unable to update user table (pond)")
		return errDatabase
	}
	return nil
}
