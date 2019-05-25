import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time
#import add_pubkey

class Login(object):

   
    def get_ping(self):
    #def authenticate(self,username,password):
        url = "http://cs302.kiwi.land/api/ping"

        #STUDENT TO UPDATE THESE...
        self = "name"
        username = "misl000"
        password = "misl000_171902940"
        publickey = "c852f14e5c063da1dbedb7fa0d6cc9e4d6f61e581140b4ae2f46cddd67556d48"
        privatekey = "2a4ec0f5a1edeca10c344b9d3558fb4cb411be6006c086252f3042a92434cf29"
        signing_key = nacl.signing.SigningKey(privatekey, encoder=nacl.encoding.HexEncoder)
        signatureMessage = bytes(publickey, encoding = 'utf-8')
        signedMessage = signing_key.sign(signatureMessage, encoder=nacl.encoding.HexEncoder)
        signature_str = signedMessage.signature.decode('utf-8')
        # Returns a public key, and its corresponding signature (sign(pubkey))
        #pubkey,signaturePing,singatureMessage,signing_key,login = add_pubkey.PublicKey.add_key(self,username,password)
        


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

        # STUDENT TO COMPLETE:
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
        return publickey,privatekey
