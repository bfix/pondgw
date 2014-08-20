Your registration at our Pond/Mail-Gateway '{{.Addr}}' FAILED!

The reason for failure is: {{.Msg}}

WHAT DOES THE FAILURE REASON MEAN?

{{if eq .Msg "Invalid public key"}}Your public key attached to the registration email is invalid and could not be read by the gateway. Check your public key and try to register again.{{else if eq .Msg "Database error"}}Your registration failed because of an internal database error. Please send a new registration mail to check if the failure is temporary; if it persists, try again after waiting a day or two, so we can fix the problem.{{else if eq .Msg "User already registered" }}You have already registered under the email address {{.User}} with a public key (see below). Please check if this is really your key; if you have not registered this account yourself, please notify us at abuse@hoi-polloi.org

{{.Key}}{{end}}
