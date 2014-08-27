#!/bin/bash

##################################################
# Generate GnuPG keypair
##################################################

rm -f *.gpg
cat >xxx <<EOF
	Key-Type: RSA
	Key-Length: 4096
	Subkey-Type: RSA
	Subkey-Length: 2048
	Name-Real: Pond/EMail Gateway
	Name-Email: pondgw@hoi-polloi.org
	Expire-Date: 0
	Passphrase: 8awzrQI4DtD39kqTk6uxqqtxjHFihVQT
EOF
ID=$(gpg --home . --gen-key --batch xxx |& grep "gpg: Schlüssel " | sed "s/gpg: Schlüssel \([^ ]*\) .*/\1/")  
rm -f xxx

gpg --home . -a --export ${ID} > public.asc 2>/dev/null
gpg --home . -a --export-secret-keys ${ID} > private.asc 2>/dev/null

rm -f random_seed *~

##################################################
# Generate self-signed SSL certificate
##################################################

openssl genrsa -out webif.key 2048
openssl req -new -key webif.key -out webif.csr
openssl x509 -req -days 720 -in webif.csr -signkey webif.key -out cert.pem -outform pem

exit 0
