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
	"fmt"
	"github.com/agl/pond/panda"
	"github.com/bfix/gospel/logger"
	"github.com/dchest/captcha"
	"html/template"
	"io/ioutil"
	"net/http"
	"regexp"
)

///////////////////////////////////////////////////////////////////////
// Module-global variables

var (
	emailRegexp *regexp.Regexp
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

	if req.Method == "POST" {
		if !captcha.VerifyString(req.FormValue("captchaId"), req.FormValue("captchaSolution")) {
			RenderPage(resp, g.config.Web.CaptchaFail, nil)
			return
		}
		if req.RequestURI == "/register/pond" {
			sharedSecret := req.FormValue("sharedSecret")
			if !panda.IsAcceptableSecretString(sharedSecret) {
				msgs = append(msgs, "You have specified an invalid shared secret")
			} else {
				id := GeneratePeerId()
				if err = g.client.StartKeyExchange(id, sharedSecret); err != nil {
					msgs = append(msgs, "Failed to start key exchange: "+err.Error())
				} else {
					_, err := InsertPondUserData(id, statPENDING)
					if err == errAlreadyRegistered {
						msgs = append(msgs, "(Temporarily) failed to register peer %s: "+err.Error())
					} else {
						param := struct {
							PeerId string
						}{
							PeerId: id,
						}
						RenderPage(resp, g.config.Tpls.PondRegSuccess, &param)
						return
					}
				}
			}
		} else if req.RequestURI == "/register/email" {
			addr := req.FormValue("emailAddress")
			if !emailRegexp.MatchString(addr) {
				msgs = append(msgs, "You have specified an invalid email address")
			}
			rdr, _, err := req.FormFile("pubKey")
			if err != nil {
				msgs = append(msgs, "You have not specified a valid GnuPG public key")
			} else {
				pubKey, err = ioutil.ReadAll(rdr)
				if err != nil {
					msgs = append(msgs, "Failed to read/validate GnuPG public key")
				}
			}
			if err == nil {
				if err = ValidateMailUser(addr, pubKey); err != nil {
					msgs = append(msgs, "Failed to send validation email")
				} else {
					param := struct {
						Addr string
					}{
						Addr: addr,
					}
					RenderPage(resp, g.config.Tpls.MailPending, &param)
					return
				}
			}
		} else {
			logger.Println(logger.INFO, "[webif] Unhandled request: "+req.URL.String())
			http.NotFound(resp, req)
		}
	} else {
		logger.Println(logger.INFO, "[webif] Unhandled request: "+req.URL.String())
		http.NotFound(resp, req)
	}
	param := struct {
		Msgs []string
	}{
		Msgs: msgs,
	}
	RenderPage(resp, g.config.Web.ErrorPage, &param)
	return
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

///////////////////////////////////////////////////////////////////////
/*
 * Start-up the HTTPS server instance.
 */
func httpsServe() {
	cfg := g.config.Web
	if len(cfg.Host) == 0 {
		logger.Println(logger.INFO, "[webif] HTTPS server disabled.")
		return
	}
	var err error
	emailRegexp, err = regexp.Compile(
		"^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*" +
			"@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")
	if err != nil {
		logger.Printf(logger.ERROR, "[webif] Faild to compile EMAIL regexp -- aborting web server: %s\n", err.Error())
		return
	}

	http.Handle("/", http.FileServer(http.Dir("./www")))
	http.HandleFunc("/register", formHandler)
	http.HandleFunc("/register/", regHandler)
	http.Handle("/captcha/", captcha.Server(captcha.StdWidth, captcha.StdHeight))

	logger.Println(logger.INFO, "[webif] Starting server on "+cfg.Host)
	if err := http.ListenAndServeTLS(cfg.Host, cfg.Cert, cfg.Key, nil); err != nil {
		logger.Println(logger.ERROR, "[webif] "+err.Error())
	}
}
