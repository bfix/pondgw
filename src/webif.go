/*
 * Handle HTTPS sessions for user registrations
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
	"encoding/hex"
	"fmt"
	"github.com/agl/pond/panda"
	"github.com/bfix/gospel/logger"
	"github.com/dchest/captcha"
	"html/template"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
)

///////////////////////////////////////////////////////////////////////
// Module-global constants and variables

const (
	mailAddrRE = "^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*" +
		"@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$"
)

var (
	emailRegexp = regexp.MustCompile(mailAddrRE)
)

///////////////////////////////////////////////////////////////////////
/*
 * Render a HTML web page from a template.
 * @param resp http.ResponseWriter - response buffer
 * @param tplName string - name of template file
 * @param data interface{} - template parameters
 * @return error - error instancve or nil
 */
func RenderPage(resp http.ResponseWriter, tplName string, data interface{}) error {
	tpl, err := template.ParseFiles(tplName)
	if err != nil {
		msg := fmt.Sprintf("Failed to read HTML template '%s': %s\n", tplName, err.Error())
		logger.Printf(logger.ERROR, msg)
		resp.Write([]byte(msg))
		return err
	}
	if err = tpl.Execute(resp, data); err != nil {
		msg := fmt.Sprintf("Failed to execute HTML template '%s': %s\n", tplName, err.Error())
		logger.Printf(logger.ERROR, msg)
		resp.Write([]byte(msg))
		return err
	}
	return nil
}

//---------------------------------------------------------------------
/*
 * Render an error page with single message
 * @param resp http.ResponseWriter - response buffer
 * @param root string - path to web root
 * @param err string - error message
 */
func ErrorPage(resp http.ResponseWriter, root, err string) {
	ErrorsPage(resp, root, []string{err})
}

//---------------------------------------------------------------------
/*
 * Render an error page with multiple messages
 * @param resp http.ResponseWriter - response buffer
 * @param root string - path to web root
 * @param err string - error message
 */
func ErrorsPage(resp http.ResponseWriter, root string, errs []string) {
	param := struct {
		Root string
		Msgs []string
	}{
		Root: root,
		Msgs: errs,
	}
	RenderPage(resp, g.config.Web.ErrorPage, &param)
}

///////////////////////////////////////////////////////////////////////
/*
 * Handle registration requests.
 * @param resp http.ResponseWriter - response buffer
 * @param req *http.Request - request data
 */
func regHandler(resp http.ResponseWriter, req *http.Request) {
	var (
		err    error
		pubKey []byte
		msgs   []string = make([]string, 0)
	)
	defer func() {
		if err != nil {
			logger.Println(logger.INFO, "[webif] Error in request handling: "+err.Error())
			http.Error(resp, err.Error(), http.StatusInternalServerError)
			return
		}
	}()

	handlePond := func() bool {
		sharedSecret := req.FormValue("sharedSecret")
		if !panda.IsAcceptableSecretString(sharedSecret) {
			msgs = append(msgs, "You have specified an invalid shared secret")
			return false
		}
		id, err := GeneratePeerId()
		if err != nil {
			msgs = append(msgs, err.Error())
			return false
		}
		if err = g.client.StartKeyExchange(id, sharedSecret); err != nil {
			msgs = append(msgs, "Failed to start key exchange: "+err.Error())
			return false
		}
		_, err = InsertPondUserData(id, statPENDING)
		if err == errAlreadyRegistered {
			msgs = append(msgs, "(Temporarily) failed to register peer %s: "+err.Error())
			return false
		}
		param := struct {
			PeerId string
		}{
			PeerId: id,
		}
		RenderPage(resp, g.config.Tpls.PondRegSuccess, &param)
		return true
	}

	handleEmail := func() bool {
		addr := req.FormValue("emailAddress")
		if !emailRegexp.MatchString(addr) {
			msgs = append(msgs, "You have specified an invalid email address")
		}
		rdr, _, err := req.FormFile("publicKey")
		if err != nil {
			msgs = append(msgs, "You have not specified a valid GnuPG public key")
			return false
		}
		pubKey, err = ioutil.ReadAll(rdr)
		if err != nil {
			msgs = append(msgs, "Failed to read GnuPG public key")
			return false
		}
		if _, err := GetPublicKey(pubKey); err != nil {
			msgs = append(msgs, "Invalid GnuPG public key")
			return false
		}
		if len(msgs) == 0 {
			if err = ValidateMailUser(addr, pubKey); err != nil {
				msg := fmt.Sprintf("Failed to send validation email to '%s': %s", addr, err.Error())
				msgs = append(msgs, msg)
				return false
			}
			param := struct {
				Addr string
			}{
				Addr: addr,
			}
			RenderPage(resp, g.config.Tpls.MailPending, &param)
			return true
		}
		return false
	}

	if req.Method == "POST" {
		if !captcha.VerifyString(req.FormValue("captchaId"), req.FormValue("captchaSolution")) {
			param := struct {
				Root string
			}{
				Root: g.config.Web.Host,
			}
			RenderPage(resp, g.config.Web.CaptchaFail, &param)
			return
		}
		if req.RequestURI == "/register/pond" {
			if handlePond() {
				return
			}
		} else if req.RequestURI == "/register/email" {
			logger.Printf(logger.DBG, "Request='%v'\n", req)
			if handleEmail() {
				return
			}
		} else {
			logger.Println(logger.INFO, "[webif] Unhandled request: "+req.URL.String())
			msgs = append(msgs, "Unhandled request")
		}
	} else {
		logger.Println(logger.INFO, "[webif] Unhandled request: "+req.URL.String())
		msgs = append(msgs, "Unhandled request")
	}
	ErrorsPage(resp, "..", msgs)
}

//---------------------------------------------------------------------
/*
 * Assemble registration form page.
 * @param resp http.ResponseWriter - response buffer
 * @param req *http.Request - request data
 */
func formHandler(resp http.ResponseWriter, req *http.Request) {
	data := struct {
		CaptchaId string
	}{
		captcha.New(),
	}
	RenderPage(resp, g.config.Web.FormPage, &data)
}

//---------------------------------------------------------------------
/*
 * Assemble usage page (tutorial).
 * @param resp http.ResponseWriter - response buffer
 * @param req *http.Request - request data
 */
func usageHandler(resp http.ResponseWriter, req *http.Request) {
	data := struct {
		GatewayEmail string
	}{
		GatewayEmail: g.config.Email.Address,
	}
	RenderPage(resp, g.config.Web.UsagePage, &data)
}

//---------------------------------------------------------------------
/*
 * Confirm email registration.
 * @param resp http.ResponseWriter - response buffer
 * @param req *http.Request - request data
 */
func confirmHandler(resp http.ResponseWriter, req *http.Request) {

	ref := "/confirm/"
	if !strings.HasPrefix(req.RequestURI, ref) {
		ErrorPage(resp, "..", "Invalid confirmation link")
		return
	}
	token := req.RequestURI[len(ref):]
	buf, err := hex.DecodeString(token)
	if err != nil || len(buf) != 16 {
		ErrorPage(resp, "..", "Invalid confirmation token")
		return
	}
	user, err := GetMailUserDataByToken(token)
	if err != nil || user.Status != statPENDING {
		ErrorPage(resp, "..", "Invalid confirmation token")
		return
	}
	err = UpdateMailUserStatus(user.Address, statREGISTERED)
	if err != nil {
		ErrorPage(resp, "..", "Failed to update user database -- try again at a later time")
		return
	}
	err = DropMailUserToken(user.Address)
	if err != nil {
		ErrorPage(resp, "..", "Failed to update user database -- try again at a later time")
		return
	}
	data := struct {
		Addr string
	}{
		Addr: user.Address,
	}
	RenderPage(resp, g.config.Tpls.MailConfirm, &data)
}

///////////////////////////////////////////////////////////////////////
/*
 * Start-up the HTTPS server instance.
 */
func httpsServe() {
	cfg := g.config.Web
	if len(cfg.Listen) == 0 {
		logger.Println(logger.INFO, "[webif] HTTPS server disabled.")
		return
	}
	http.Handle("/", http.FileServer(http.Dir(g.config.Web.Docs)))
	http.HandleFunc("/usage", usageHandler)
	http.HandleFunc("/register", formHandler)
	http.HandleFunc("/register/", regHandler)
	http.HandleFunc("/confirm/", confirmHandler)
	http.Handle("/captcha/", captcha.Server(captcha.StdWidth, captcha.StdHeight))

	logger.Println(logger.INFO, "[webif] Starting server on "+cfg.Listen)
	if err := http.ListenAndServeTLS(cfg.Listen, cfg.Cert, cfg.Key, nil); err != nil {
		logger.Println(logger.ERROR, "[webif] "+err.Error())
	}
}
