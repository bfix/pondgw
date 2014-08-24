Congratulations -- your registration at our Pond/Mail-Gateway '{{.Addr}}' was successful.

Please import our attached OpenPGP public key to your keyring. You will need this key to encrypt all further emails to us. Unencrypted (and unsigned) emails are not processed and discarded without further notice.

Please ask your peers on Pond servers to provide you with their Pond identity (that is a 32 byte hexadecimal number) and their Pond server URL (onion address). Also ask them to register on our gateway so you both cvan excange messages. Also ask them for a public OpenPGP key that they should create exclusively for message exchange with you and that should *not* be uploaded to a keyserver.

HOW TO SEND MESSAGES TO A POND USER:

(1) Write a plain text message not longer than 15,000 characters.

(2) [Optional, but highly recommended] Encrypt the message with the public key of the recipient and output the result in armored (ASCII) format

(3) Copy the encrypted text into your email body.

(4) Add a line at the top (first line) to specify the Pond recipient:

    To: XXXXXX

The recipient is identified by a short string; ask your Pond peer(s) for theirs. 

(5) Leave the subject of the email empty and sign and encrypt the message before sending it to the gateway email address

N.B.: We suggest to create email drafts (templates) for each of the Pond users you want to communicate with and specify the first line as specified above. This makes sending messages to your Pond peers easier.

Enjoy the Pond/EMail-Gateway.
