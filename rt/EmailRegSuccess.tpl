Congratulations -- your registration at our Pond/Mail-Gateway '{{.Addr}}' was successful.

Please import our attached OpenPGP public key to your keyring. You will need this key to encrypt all further emails to us. Unencrypted (and unsigned) emails are not processed and discarded without further notice.

Please ask your peers on Pond servers to provide you with their Pond identity (that is a 32 byte hexadecimal number) and their Pond server URL (onion address). Also ask them to register on our gateway so you both cvan excange messages. Also ask them for a public OpenPGP key that they should create exclusively for message exchange with you and that should *not* be uploaded to a keyserver.

HOW TO SEND MESSAGES TO A POND USER:

(1) Write a plain text message not longer than 15,000 characters.

(2) Encrypt the message with the public key of the recipient and output the result in armored (ASCII) format

(3) Copy the encrypted text into your email body.

(4) Insert two lines at the top of the body to specify the recipient:

    Identity:5f480f64c591a00ba0bc555bc8a95fb7c32606a7d800abd98eec476c490974e8
    Server:4V6Q5M2AFLBW6UIYL2B5LMKDHEBA6HRHR6UIUU3VDQFNI3BHZAEQ@oum7argqrnlzpcro.onion
    
(5) Leave the subject empty and sign and encrypt the message before sending it to the gateway email address

N.B.: We suggest to create email drafts (templates) for each of the Pond users you want to communicate with and specify the first two lines as specified above. This makes sending messages to your Pond peers easier.

Enjoy the Pond/EMail-Gateway.
