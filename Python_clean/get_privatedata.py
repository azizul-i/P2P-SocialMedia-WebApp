import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time
import nacl.secret
import nacl.utils

class private(object):

   
    def get_encoded_data(self):
    #def authenticate(self,username,password):
        url = "http://cs302.kiwi.land/api/get_privatedata"

        #STUDENT TO UPDATE THESE...
        username = "misl000"
        password = "misl000_171902940"
        loginserver_record = 'misl000,c852f14e5c063da1dbedb7fa0d6cc9e4d6f61e581140b4ae2f46cddd67556d48,1558689185.3489795,4625731f1a7396bcffad7b68da2c0de8fcc222663f8ac75bd88597ac4dfdaa2fced2d4e841e86f1d316bf9c010dd4e6bc005f70ee7558546e0d7b76a3af9ff01'
        client_saved_at = str(time.time())


        #SecretBox generation
        #key = b'\x83\xebug\x86\x8d\x9b#\xfdRqY\xe7\xf6\x01$\x844\x9a+\xaf\x08O\xf7O\xd9\xe3;\xd2\xdc`\xf5'
        #message = "0f1cee12a9da62ae84b93d766393388d70b8fac374d1af4b8fa7a53e98aeecaa8bf5952376a5f8cd0a951edc3e4e65a92beb1baee5206d1647b4638c6fcf2d417238c97ab33a5f626abb1d3b572ef37ae902ac3cab620140e865b9081bcda92e1a240dddef039546516012102b9f7ae0f2bebdab44d1a8aba6b37f30f6867096d59fd2fc906e5991a220ba80edebe936eeec304ceaa186dca4eb9269b87ab88502781d54ae396a6471bd2aaefd23643d789741ecc679aaa192860905f1a243e08d5319634d62e9e0235837bc3017ae6e9b5c7ce39939d8d8147edea2c3d3fecfb6f0fe039866fb0c64966988a6fa8167c3135cc3465d418522a10b4dde3ae44c72078f5328fa9b15c0eb82b7fd5aa63aa83e70a1c99179ce8020080a1ae5432644c9a3539df948a6d8aae6f9659a6b94cf18e678a498b40d3765f73a273954e20400dc14a75d68542c36152fd91b3a3213e7ec7bfe86202f5cb542f17eed7fb2d09bc8ec6316cb16fd59de9d"
        #box = nacl.secret.SecretBox(key)
        #plaintext = box.decrypt(message,nonce=None, encoder=nacl.encoding.HexEncoder)
        #print(str(plaintext))

        # Returns a public key, and its corresponding signature (sign(pubkey))
        #pubkey,signaturePing,singatureMessage,signing_key,login = add_pubkey.PublicKey.add_key(self,username,password)


        
        # create HTTP BASIC authorization header
        credentials = ('%s:%s' % (username, password))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'Content-Type': 'application/json; charset=utf-8',
            
        }

        payload = {
            

 
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
        return JSON_object["privatedata"]
        #print(JSON_object)
        #return JSON_object["privatedata"]
 