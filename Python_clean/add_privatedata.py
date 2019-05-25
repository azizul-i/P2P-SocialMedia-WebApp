import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time
import nacl.secret
import nacl.utils

class private(object):


        """ Use this API to save symmetrically encrypted private data for a given user. It will
            automatically delete previously uploaded private data. """
        url = "http://cs302.kiwi.land/api/add_privatedata"

        # User details
        username = "misl000"
        password = "misl000_171902940"
        loginserver_record = 'misl000,c852f14e5c063da1dbedb7fa0d6cc9e4d6f61e581140b4ae2f46cddd67556d48,1558689185.3489795,4625731f1a7396bcffad7b68da2c0de8fcc222663f8ac75bd88597ac4dfdaa2fced2d4e841e86f1d316bf9c010dd4e6bc005f70ee7558546e0d7b76a3af9ff01'
        client_saved_at = str(time.time())


        #SecretBox generation
        key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        print(key) # Keep this key safe!!!
        box = nacl.secret.SecretBox(key)
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        
        
        privatedata = { 
                        "prikeys": ["2a4ec0f5a1edeca10c344b9d3558fb4cb411be6006c086252f3042a92434cf29", "..."],
                        "blocked_pubkeys": ["...", "..."],
                        "blocked_usernames": ["...", "..."],
                        "blocked_words": ["...", "..."],
                        "blocked_message_signatures": ["...", "..."],
                        "favourite_message_signatures": ["...", "..."],
                        "friends_usernames": ["...", "..."]
                     }

        # Converts private data to string
        privatedata = json.dumps(privatedata) 

        # Converts to bytes
        privatedata = bytes(privatedata, encoding='utf-8') 

        # Encrypt the private data
        encrypted_privatedata = box.encrypt(privatedata,nonce=None, encoder=nacl.encoding.HexEncoder).decode('utf-8')
        
        # Get private key 
        privatekey = "2a4ec0f5a1edeca10c344b9d3558fb4cb411be6006c086252f3042a92434cf29"
        
        # Make signing key
        signing_key = nacl.signing.SigningKey(privatekey, encoder=nacl.encoding.HexEncoder)
        
        # Signing message
        signatureMessage = bytes(encrypted_privatedata + loginserver_record + client_saved_at, encoding = 'utf-8')
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
            
            "privatedata": encrypted_privatedata,
            "loginserver_record": loginserver_record,
            "client_saved_at": client_saved_at,
            "signature": signature_str,
 
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
 