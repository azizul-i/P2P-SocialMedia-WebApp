import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time


class Ping(object):
    #def pinging(self, username, password):
    # Tests whether the Login server is online, and tests signing/authentication
    #def get_ping(self):
        url = "http://cs302.kiwi.land/api/ping"

        # Need to check with Hammond
        #self = "name"
        # Should be inputed from personal web api
        username = "misl000"
        password = "misl000_171902940"


        publickey = "c852f14e5c063da1dbedb7fa0d6cc9e4d6f61e581140b4ae2f46cddd67556d48"

        # Utilise get private data endpoint
        privatekey = "2a4ec0f5a1edeca10c344b9d3558fb4cb411be6006c086252f3042a92434cf29"

        # Creates a signing key from encoded private key
        signing_key = nacl.signing.SigningKey(privatekey, encoder=nacl.encoding.HexEncoder)

        # Creates a message to be signed (pubkey)
        signatureMessage = bytes(publickey, encoding = 'utf-8')

        # Signs message using signing key and encodes it
        signedMessage = signing_key.sign(signatureMessage, encoder=nacl.encoding.HexEncoder)

        # Decodes it into string 
        signature_str = signedMessage.signature.decode('utf-8')
        
        


        # create HTTP BASIC authorization header
        credentials = ('%s:%s' % (username, password))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'Content-Type': 'application/json; charset=utf-8',
            #'X-signature': signature_str,
            
        }

        payload = {
            
            "pubkey": publickey,
            "signature": signature_str,
 
        }

        # converts the payload into json representation,
        payload_str = json.dumps(payload)

        # ensures the payload is in bytes, not a string
        json_payload = payload_str.encode('utf-8')

        # passes the payload bytes into this function
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
        #return publickey,privatekey
