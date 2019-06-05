import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time
import nacl.secret
import nacl.utils
import Get_Loginserver_records
import nacl.pwhash

class private(object):


        """ Use this API to save symmetrically encrypted private data for a given user. It will
            automatically delete previously uploaded private data. """
        url = "http://cs302.kiwi.land/api/add_privatedata"
        self = "name"
        # User details
        username = "misl000"
        password = "misl000_171902940"
        loginserver_record = Get_Loginserver_records.Serverkey.get_loginrecord(self,username,password)
        client_saved_at = str(time.time())


        #SecretBox generation
        
        #key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        #print(key) # Keep this key safe!!!
        # box = nacl.secret.SecretBox(key)
        # nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

        key_password = "password"
        salt_password = bytes((key_password * 16).encode('utf-8')[:16])
        key_password_b = bytes(key_password, encoding='utf-8')
        ops = nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE
        mems = nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE
        #symmetric_key = nacl.pwhash.argon2i.kdf(32,key_password_b,salt_password,ops,mems, encoder=nacl.encoding.HexEncoder)
        symmetric_key = nacl.pwhash.argon2i.kdf(32,key_password_b,salt_password,ops,mems)
        print(symmetric_key)
        box = nacl.secret.SecretBox(symmetric_key)
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

        
        
        privatedata = { 
                        "prikeys": ["2a4ec0f5a1edeca10c344b9d3558fb4cb411be6006c086252f3042a92434cf29"],
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
        encrypted_privatedata = box.encrypt(privatedata,nonce, encoder=nacl.encoding.HexEncoder).decode('utf-8')
        
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
 