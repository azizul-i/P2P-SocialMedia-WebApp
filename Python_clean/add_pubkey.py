import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time

class PublicKey(object):

    #def add_key(self,username,password):

        """ Use this API to associate a public key (256-bit Ed25519 format, hex encoded) with
            your account. The public key that is added is the one provided for the purposes of the
            signature. """
        url = "http://cs302.kiwi.land/api/add_pubkey"
        username = "misl000"
        password = "misl000_171902940"

        # Generate new private key
        signing_key = nacl.signing.SigningKey.generate()

        # Generate public key from private key
        verify_key = signing_key.verify_key

        # Make private key encoded
        private_key = signing_key.encode(encoder=nacl.encoding.HexEncoder)
        print(private_key)

        # Hex Encoded public key
        verify_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)
        publicKey = verify_key_hex.decode('utf-8')

        # Sign message with public key and username
        signatureMessage = bytes(publicKey + username, encoding = 'utf-8')
        signedMessage = signing_key.sign(signatureMessage, encoder=nacl.encoding.HexEncoder)
        signature_str = signedMessage.signature.decode('utf-8')


        # create HTTP BASIC authorization header
        credentials = ('%s:%s' % (username, password))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'Content-Type': 'application/json; charset=utf-8',
            'X-signature': signature_str,
            
        }

        payload = {
            "pubkey": publicKey,
            "username": username,
            "signature": signature_str,
            "client_time": time.time()


        }


        # 1. convert the payload into json representation,
        payload_str = json.dumps(payload)
        
        # 2. ensure the payload is in bytes, not a string
        json_payload = payload_str.encode('utf-8')

        # 3. pass the payload bytes into this function
        try:
            req = urllib.request.Request(url, data=json_payload, headers=headers)
            response = urllib.request.urlopen(req)
            data = response.read()  # read the received bytes
            # load encoding if possible (default to utf-8)
            encoding = response.info().get_content_charset('utf-8')
            response.close()
        except urllib.error.HTTPError as error:
            print(error.read())
            exit()

        JSON_object = json.loads(data.decode(encoding))
        print(JSON_object)
        login_record = JSON_object
        print(signing_key)
        #return publicKey,signaturePing_str,signature_str, signing_key,JSON_object["loginserver_record"]
