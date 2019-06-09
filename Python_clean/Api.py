import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import nacl.pwhash
import sqlite3
import nacl.secret
import nacl.public
import time
import data
import socket
import nacl.hash


class Api(object):
    def ping_EP(self, username, api_key,publickey,privatekey):
        url = "http://cs302.kiwi.land/api/ping"

        error = []
        # Need to check with Hammond
        #self = "name"
        # Should be inputed from personal web api
        #username = "misl000"
        #password = "misl000_171902940"


        #publickey = "c852f14e5c063da1dbedb7fa0d6cc9e4d6f61e581140b4ae2f46cddd67556d48"

        # Utilise get private data endpoint
        #privatekey = "2a4ec0f5a1edeca10c344b9d3558fb4cb411be6006c086252f3042a92434cf29"

        # Creates a signing key from encoded private key
        try:
            signing_key = nacl.signing.SigningKey(privatekey, encoder=nacl.encoding.HexEncoder)
        except:
            error.append("invalid_privkey")

        try:
        # Creates a message to be signed (pubkey)
            signatureMessage = bytes(publickey, encoding = 'utf-8')

        # Signs message using signing key and encodes it
            signedMessage = signing_key.sign(signatureMessage, encoder=nacl.encoding.HexEncoder)

        # Decodes it into string 
            signature_str = signedMessage.signature.decode('utf-8')
        
        except:
            publickey = "None"
            signature_str = "None"
            error.append("incorrect_pubkey_sign")



        # create HTTP BASIC authorization header
        #credentials = ('%s:%s' % (username, password))
        #b64_credentials = base64.b64encode(credentials.encode('ascii'))
        
        headers = {
            #'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            
            'X-username': username,
            'X-apikey': api_key,
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
            exit()

        JSON_object = json.loads(data.decode(encoding))
        print(JSON_object)
    
    def report_EP(self,username,api_key,status,pubkey):
        url = "http://cs302.kiwi.land/api/report"

        # Credentials use server to update
        #username = "misl000"
        #password = "misl000_171902940"

        # current public key
        #pubkey = "c852f14e5c063da1dbedb7fa0d6cc9e4d6f61e581140b4ae2f46cddd67556d48"

        # connections
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        connection_address = "192.168.87.21:10050"
        connection_location = "2"

        # create HTTP BASIC authorization header
        #credentials = ('%s:%s' % (username, password))
        #b64_credentials = base64.b64encode(creden
        # tials.encode('ascii'))
        headers = {
            #'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'X-username': username,
            'X-apikey': api_key,
            'Content-Type': 'application/json; charset=utf-8',

            
        }

        payload = {
            "connection_address": connection_address,
            "connection_location": connection_location,
            "incoming_pubkey":pubkey,
            "status": status,


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
        print(status)
        print(JSON_object)
        return JSON_object["response"]   
    
    def list_apis_EP(self):
        url = "http://cs302.kiwi.land/api/list_apis"

        try:
            req = urllib.request.Request(url)
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
        return JSON_object

    def load_new_apikey_EP(self,username,password):
         # endpoint and credentials
        url = "http://cs302.kiwi.land/api/load_new_apikey"
        #username = "misl000"
        #password = "misl000_171902940"


        
        # create HTTP BASIC authorization header
        credentials = ('%s:%s' % (username, password))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'Content-Type': 'application/json; charset=utf-8',
            
        }

        payload = {

        }


        # 1. convert the payload into json representation,
        payload_str = json.dumps(payload)
        
        # 2. ensure the payload is in bytes, not a string
        json_payload = payload_str.encode('utf-8')

        # 3. pass the payload bytes into this function
        try:
            req = urllib.request.Request(url, headers=headers)
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
        return JSON_object["response"],JSON_object["api_key"]

    def loginserver_pubkey_EP(self):
        url = "http://cs302.kiwi.land/api/loginserver_pubkey"

        try:
            req = urllib.request.Request(url)
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
        return JSON_object

    def list_users_EP(self,username,api_key):
        url = "http://cs302.kiwi.land/api/list_users"

        headers = {
            'X-username': username,
            'X-apikey': api_key,
            'Content-Type': 'application/json; charset=utf-8',
            
        }

        payload = {

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
        username = []
        connection_address = []
        connection_location = []
        updated_time = []
        publickey = []
        status = []
        online_records = []
        users = JSON_object["users"]
        #print(users)
        for record in range(len(users)):
            #print(users[record])
            username.append(users[record]["username"])
            connection_address.append(users[record]["connection_address"])
            connection_location.append(users[record]["connection_location"])
            updated_time.append(users[record]["connection_updated_at"])
            publickey.append(users[record]["incoming_pubkey"])
            status.append(users[record]["status"])

        online_users = {
            "username":username,
            "connection_address":connection_address,
            "connection_location":connection_location,
            "connection_updated_at":updated_time,
            "publickey": publickey,
            "status":status
        }

        print("******************************************")
        print(online_users)
        print("*******************************************")

     
        return online_users
        #print(username)
        #print(status)
        #print(online_records)
        #for i in range(len(username)):
            #print(username[i])


    def get_loginserver_record_EP(self,username,api_key):
        url = "http://cs302.kiwi.land/api/get_loginserver_record"

        # Credentials use server to update
        #username = "misl000"
        #password = "misl000_171902940"

        # create HTTP BASIC authorization header
        #credentials = ('%s:%s' % (username, password))
        #b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            #'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'X-username': username,
            'X-apikey': api_key,
            'Content-Type': 'application/json; charset=utf-8',

            
        }

        payload = {


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
        return JSON_object["loginserver_record"] 
        
    def check_pubkey_EP(self,username,api_key,peer_pubkey):


        # endpoint and credentials
        url = "http://cs302.kiwi.land/api/check_pubkey?pubkey=" + peer_pubkey



        # create HTTP BASIC authorization header
        #credentials = ('%s:%s' % (username, password))
        #b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
        #    'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'X-username': username,
            'X-apikey': api_key,
            'Content-Type': 'application/json; charset=utf-8',
            
        }

        payload = {

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
     
        return JSON_object

    def add_privatedata(self,username,api_key, login_record,privatekey,password,friend_username="none",blocked_words="none"): 
        """ Use this API to save symmetrically encrypted private data for a given user. It will
            automatically delete previously uploaded private data. """
        url = "http://cs302.kiwi.land/api/add_privatedata"

        loginserver_record = str(login_record)
        client_saved_at = str(time.time())
        print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")
        print("ADDING NEW PRIVATE DATA: " + privatekey)
        print("$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$")

        #SecretBox generation
        
        #key = nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE)
        #print(key) # Keep this key safe!!!
        # box = nacl.secret.SecretBox(key)
        # nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

        key_password = password
        salt_password = bytes(((key_password * 16).encode('utf-8')[:16]))
        key_password_b = bytes(key_password, encoding='utf-8')
        ops = nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE
        mems = nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE
        #symmetric_key = nacl.pwhash.argon2i.kdf(32,key_password_b,salt_password,ops,mems, encoder=nacl.encoding.HexEncoder)
        # implement key.size
        symmetric_key = nacl.pwhash.argon2i.kdf(nacl.secret.SecretBox.KEY_SIZE,key_password_b,salt_password,ops,mems)
        print(symmetric_key)
        box = nacl.secret.SecretBox(symmetric_key)
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        prikeys = [str(privatekey)]
        blocked_pubkeys = []
        blocked_usernames = []
        blocked_words = []
        blocked_message_signatures = []
        favourite_message_signatures = []
        friends_usernames = []

        #keys, record = Api.decode_privatedata(self,username,api_key,password)

        if friend_username != "none":
            try:
                print("CHECK")
                keys, record = Api.decode_privatedata(self,username,api_key,password)
                print("CHECK")
                blocked_pubkeys = record["blocked_pubkeys"]
                print("CHECK")
                blocked_usernames = record["blocked_usernames"]
                print("CHECK")
                blocked_words = record["blocked_words"]
                print("CHECK")
                blocked_message_signatures = record["blocked_message_signatures"]
                print("CHECK")
                favourite_message_signatures = record["favourite_message_signatures"]
                print("CHECK")
                friends_usernames = record["friends_usernames"]
                print("CHECK")
                #prikeys = record["prikeys"]
                print("CHECK")
            except:
                print("------------------------")
                print("Could not obtain record")
                print("------------------------")
        
        

        for i in range(len(friends_usernames)):
            if friend_username[i] != "none":
                friends_usernames.append(friend_username)
        #friends_usernames = []

        privatedata = { 
                        "prikeys": prikeys,
                        "blocked_pubkeys": blocked_pubkeys,
                        "blocked_usernames": blocked_usernames,
                        "blocked_words": blocked_words,
                        "blocked_message_signatures": blocked_message_signatures,
                        "favourite_message_signatures": favourite_message_signatures,
                        "friends_usernames": friends_usernames
                     }



        print("TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT")
        print(privatedata)
        print("TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT")
        # Converts private data to string
        privatedata = json.dumps(privatedata) 
        
        # Converts to bytes
        privatedata = bytes(privatedata, encoding='utf-8') 
        #privatedata = base64.b64encode(privatedata

        # Encrypt the private data
        encrypted_privatedata = box.encrypt(privatedata,nonce, encoder=nacl.encoding.Base64Encoder).decode('utf-8')
        
        # Get private key 
        #privatekey = "2a4ec0f5a1edeca10c344b9d3558fb4cb411be6006c086252f3042a92434cf29"
        
        # Make signing key
        signing_key = nacl.signing.SigningKey(privatekey, encoder=nacl.encoding.HexEncoder)
        
        # Signing message
        signatureMessage = bytes(encrypted_privatedata + loginserver_record + client_saved_at, encoding = 'utf-8')
        signedMessage = signing_key.sign(signatureMessage, encoder=nacl.encoding.HexEncoder)
        signature_str = signedMessage.signature.decode('utf-8')

        # create HTTP BASIC authorization header
        #credentials = ('%s:%s' % (username, password))
        #b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            #'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            #'X-signature': signature_str,
            'X-username': username,
            'X-apikey': api_key,
            'Content-Type': 'application/json; charset=utf-8',
            
            
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

    def get_privatedata(self,username,api_key):
        """Use this API to load the saved symmetrically encrypted private data for a user """
        #def authenticate(self,username,password):

        # Endpoint
        url = "http://cs302.kiwi.land/api/get_privatedata"



        # create HTTP BASIC authorization header
        #credentials = ('%s:%s' % (username, password))
        #b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'X-username':username,
            'X-apikey':api_key,
            'Content-Type': 'application/json; charset=utf-8',
            
        }

        payload = {
            

 
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
        return JSON_object["privatedata"]


    def decode_privatedata(self,username,api_key, box_password):
        key_password = box_password
        salt_password = bytes((key_password * 16).encode('utf-8')[:16])
        key_password_b = bytes(key_password, encoding='utf-8')
        print(key_password_b)
        print(salt_password)
        ops = nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE
        mems = nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE

        #symmetric_key = nacl.pwhash.argon2i.kdf(32,key_password_b,salt_password,ops,mems, encoder=nacl.encoding.HexEncoder)
        symmetric_key = nacl.pwhash.argon2i.kdf(32,key_password_b,salt_password,ops,mems)
        print(box_password)
        print(key_password_b)
        print(salt_password)
        print(ops)
        print(mems)
        print(symmetric_key)
        message = Api.get_privatedata(self,username,api_key)
        box = nacl.secret.SecretBox(symmetric_key)
        plaintext = box.decrypt(message,nonce=None, encoder=nacl.encoding.Base64Encoder)
        print(str(plaintext))
        private_data = json.loads(str(plaintext.decode('utf-8')))
        #tmp_dict = dict(tmp)
        #p_keys = ','.join(map(str,tmp["prikeys"]))
        #print(p_keys)
        print("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
        print(private_data)
        p_keys = (private_data["prikeys"])
        p_keys = str(p_keys[0])
        return p_keys,private_data
    
    def generate_pubkey(self,privatekey):

        signing_key = nacl.signing.SigningKey(privatekey, encoder=nacl.encoding.HexEncoder)
        verify_key = signing_key.verify_key
        verify_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)
        publicKey = verify_key_hex.decode('utf-8')

        return publicKey
    
    def add_pubkey_EP(self,username,api_key):
        #def add_key(self,username,password):

        """ Use this API to associate a public key (256-bit Ed25519 format, hex encoded) with
            your account. The public key that is added is the one provided for the purposes of the
            signature. """
        url = "http://cs302.kiwi.land/api/add_pubkey"


        # Generate new private key
        signing_key = nacl.signing.SigningKey.generate()

        # Generate public key from private key
        verify_key = signing_key.verify_key

        # Make private key encoded
        private_key = signing_key.encode(encoder=nacl.encoding.HexEncoder)
        

        # Hex Encoded public key
        verify_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)
        publicKey = verify_key_hex.decode('utf-8')

        # Sign message with public key and username
        signatureMessage = bytes(publicKey + username, encoding = 'utf-8')
        signedMessage = signing_key.sign(signatureMessage, encoder=nacl.encoding.HexEncoder)
        signature_str = signedMessage.signature.decode('utf-8')


        # create HTTP BASIC authorization header
        #credentials = ('%s:%s' % (username, password))
        #b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'X-username':username,
            'X-apikey':api_key,
            'X-signature': signature_str,
            'Content-Type': 'application/json; charset=utf-8',
            
            
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
        return publicKey,private_key.decode('utf-8')


    def rx_broadcast(self,username,api_key, privatekey, loginrecord ,message, connection_address):
        """Use this API to transmit a signed broadcast between users. You need to be
           authenticated, and the broadcast public key must be known, but the broadcast public key
           need not be associated to your account."""

        # replace URL with specific connection
        #url = "http://cs302.kiwi.land/api/rx_broadcast"
        print(connection_address)
        url = "http://" + connection_address + "/api/rx_broadcast"
        #username = "misl000"
        #password = "misl000_171902940"
    
        # Load public and private keys
        #publickey = "c852f14e5c063da1dbedb7fa0d6cc9e4d6f61e581140b4ae2f46cddd67556d48"

        # Load login record
        # get private key from private data to generate signing key
        signing_key = nacl.signing.SigningKey(privatekey, encoder=nacl.encoding.HexEncoder)
        verify_key = signing_key.verify_key
        verify_key_hex = verify_key.encode(encoder=nacl.encoding.HexEncoder)
        publicKey = verify_key_hex.decode('utf-8')

        # get timestamp
        sender_created_at = str(time.time())

        # record broadcast message (tweet)
        #message = "Combination Test2"
    
        # Message signing
        signatureMessage = bytes(loginrecord + message + sender_created_at, encoding = 'utf-8')
        signedMessage = signing_key.sign(signatureMessage, encoder=nacl.encoding.HexEncoder)
        signature_str = signedMessage.signature.decode('utf-8')
        

        # create HTTP BASIC authorization header
        #credentials = ('%s:%s' % (username, password))
        #b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'X-username': username,
            'X-apikey': api_key,
            'Content-Type': 'application/json; charset=utf-8',
        }

        payload = {
            "loginserver_record":loginrecord,
            "message": message,
            "sender_created_at" : sender_created_at,
            "signature": signature_str,
        
        }


        # 1. convert the payload into json representation,
        payload_str = json.dumps(payload)
        # 2. ensure the payload is in bytes, not a string
        json_payload = payload_str.encode('utf-8')

        # 3. pass the payload bytes into this function
        try:
            req = urllib.request.Request(url, data=json_payload, headers=headers)
            response = urllib.request.urlopen(req, timeout=0.1)
            data = response.read()  # read the received bytes
            # load encoding if possible (default to utf-8)
            encoding = response.info().get_content_charset('utf-8')
            response.close()
        except urllib.error.HTTPError as error:
            print(error.read())
            exit()

        JSON_object = json.loads(data.decode(encoding))
        print(JSON_object)

    def encrypted_message(self,username,pubkey,t_message):
        target_key = nacl.signing.VerifyKey(pubkey,encoder=nacl.encoding.HexEncoder).to_curve25519_public_key()
        box = nacl.public.SealedBox(target_key)
        message = bytes(t_message,encoding = 'utf-8')
        encrypted_message = box.encrypt(message, encoder=nacl.encoding.HexEncoder).decode('utf-8')
        return encrypted_message


    def rx_privatemessage(self,username,apikey,pubkey,privkey,login_record, t_user, t_pubkey,t_message,t_connection_address):
        """ Use this API to transmit a secret message between users. Meta-information is
            public (the sender username/pubkey, and the destination username/pubkey, the timestamp). """
        url = "http://"+ t_connection_address + "/api/rx_privatemessage"
        print("XXXXXXXXXXXXXXXXX")
        print(t_connection_address)
        print("XXXXXXXXXXXXXXXXX")

        # timestamp
        sender_created_at = str(time.time())

        # target details
        target_username = t_user
        target_pubkey = t_pubkey

        # Generate encrypting public key
        target_key = nacl.signing.VerifyKey(target_pubkey,encoder=nacl.encoding.HexEncoder).to_curve25519_public_key()
        personal_key = nacl.signing.VerifyKey(pubkey,encoder=nacl.encoding.HexEncoder).to_curve25519_public_key()
        # Make sealed box using public key (can only be decoded by target)
        box = nacl.public.SealedBox(target_key)
        personal_box = nacl.public.SealedBox(personal_key)

        target_key_str = target_key.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')

        # Private message that needs to be encrypted
        message = bytes(t_message,encoding = 'utf-8')
        encrypted_message = box.encrypt(message, encoder=nacl.encoding.HexEncoder).decode('utf-8')
        personal_encrypted_message = personal_box.encrypt(message, encoder=nacl.encoding.HexEncoder).decode('utf-8')

        # Create signing key from private key
        publickey = pubkey
        privatekey = privkey
        login = str(login_record)
        signing_key = nacl.signing.SigningKey(privatekey, encoder=nacl.encoding.HexEncoder)
        sender_created_at = str(time.time())
        
        #publicKey,signaturePing_str,signature_str,signing_key,login = add_pubkey.PublicKey.add_key(self,username,password)
        
        # Sign message (login,targetkey,targetusernmae,encryptedmessage,sender_created_at)
        signatureMessage = bytes(login + target_pubkey + target_username + encrypted_message + sender_created_at, encoding = 'utf-8')
        signedMessage = signing_key.sign(signatureMessage, encoder=nacl.encoding.HexEncoder)
        signature_str = signedMessage.signature.decode('utf-8')
        

        # create HTTP BASIC authorization header
        #credentials = ('%s:%s' % (username, password))
        #b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'X-username': username,
            'X-apikey': apikey,
            'Content-Type': 'application/json; charset=utf-8',
        }

        payload = {
            "loginserver_record":login,
            "target_pubkey":target_pubkey,
            "target_username":target_username,
            "encrypted_message": encrypted_message,
            "sender_created_at" : sender_created_at,
            "signature": signature_str,
        
        }

        # 1. convert the payload into json representation,
        payload_str = json.dumps(payload)
        
        # 2. ensure the payload is in bytes, not a string
        json_payload = payload_str.encode('utf-8')

        # 3. pass the payload bytes into this function
        try:
            req = urllib.request.Request(url, data=json_payload, headers=headers)
            response = urllib.request.urlopen(req, timeout=2)
            data = response.read()  # read the received bytes
            # load encoding if possible (default to utf-8)
            encoding = response.info().get_content_charset('utf-8')
            response.close()
        except urllib.error.HTTPError as error:
            print(error.read())
            exit()

        JSON_object = json.loads(data.decode(encoding))
        print(JSON_object)
        return payload,personal_encrypted_message

    def decrypt_private_message(self,privatekey,encrypted_message):
        print(privatekey)
        unseal_key = nacl.signing.SigningKey(privatekey,encoder=nacl.encoding.HexEncoder).to_curve25519_private_key()
        unseal_box = nacl.public.SealedBox(unseal_key)
        plain_text = unseal_box.decrypt(encrypted_message, encoder=nacl.encoding.HexEncoder).decode('utf-8')
        return plain_text


    def tx_groupinvite(self, username, apikey, loginserver_record,target_pubkey,target_username, privatekey, pubkey, connections):
        """ Use this API to transmit a secret message between users. Meta-information is
            public (the sender username/pubkey, and the destination username/pubkey, the timestamp). """
        url = "http://" + connections + "/api/groupinvite"
        print("XXXXXXXXXXXXXXXXX")
        print(connections)
        print("XXXXXXXXXXXXXXXXX")

        ## LOGIN RECORD DONE

        #MAKE GROUPKEY HASH

        #TARGET PUBKEY DONE
        target_pubkey = target_pubkey

        #TARGET USERNAME DONE
        target_username = target_username
        #ENCRYPTED GROUPKEY

        # timestamp
        sender_created_at = str(time.time())

        # target details
        key_password = "ikea"
        salt_password = bytes((key_password * 16).encode('utf-8')[:16])
        key_password_b = bytes(key_password, encoding='utf-8')
        print(key_password_b)
        print(salt_password)
        ops = nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE
        mems = nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE

        #symmetric_key = nacl.pwhash.argon2i.kdf(32,key_password_b,salt_password,ops,mems, encoder=nacl.encoding.HexEncoder)
        symmetric_key = nacl.pwhash.argon2i.kdf(32,key_password_b,salt_password,ops,mems)
        print(key_password)
        print(key_password_b)
        print(salt_password)
        print(ops)
        print(mems)
        print(symmetric_key)
        #message = Api.get_privatedata(self,username,api_key)
        groupkey_hash = nacl.hash.sha256(symmetric_key, encoder=nacl.encoding.HexEncoder)
        print(groupkey_hash)

        # Generate encrypting public key
        target_key = nacl.signing.VerifyKey(target_pubkey,encoder=nacl.encoding.HexEncoder).to_curve25519_public_key()
        personal_key = nacl.signing.VerifyKey(pubkey,encoder=nacl.encoding.HexEncoder).to_curve25519_public_key()
        # Make sealed box using public key (can only be decoded by target)
        box = nacl.public.SealedBox(target_key)
        personal_box = nacl.public.SealedBox(personal_key)

        #target_key_str = target_key.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')

        # Private message that needs to be encrypted
        key = bytes(symmetric_key,encoding = 'utf-8')
        encrypted_groupkey = box.encrypt(key, encoder=nacl.encoding.HexEncoder).decode('utf-8')
        personal_encrypted_message = personal_box.encrypt(key, encoder=nacl.encoding.HexEncoder).decode('utf-8')

        # Create signing key from private key
        signing_key = nacl.signing.SigningKey(privatekey, encoder=nacl.encoding.HexEncoder)
        sender_created_at = str(time.time())
        
        #publicKey,signaturePing_str,signature_str,signing_key,login = add_pubkey.PublicKey.add_key(self,username,password)
        
        # Sign message (login,targetkey,targetusernmae,encryptedmessage,sender_created_at)  
        signatureMessage = bytes(loginserver_record + groupkey_hash + target_pubkey + target_username + encrypted_groupkey + sender_created_at, encoding = 'utf-8')
        signedMessage = signing_key.sign(signatureMessage, encoder=nacl.encoding.HexEncoder)
        signature_str = signedMessage.signature.decode('utf-8')
        

        # create HTTP BASIC authorization header
        #credentials = ('%s:%s' % (username, password))
        #b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'X-username': username,
            'X-apikey': apikey,
            'Content-Type': 'application/json; charset=utf-8',
        }

        payload = {
            "loginserver_record":loginserver_record,
            "groupkey_hash": groupkey_hash,
            "target_pubkey":target_pubkey,
            "target_username":target_username,
            "encrypted_groupkey": encrypted_groupkey,
            "sender_created_at" : sender_created_at,
            "signature": signature_str,
        
        }

        # 1. convert the payload into json representation,
        payload_str = json.dumps(payload)
        
        # 2. ensure the payload is in bytes, not a string
        json_payload = payload_str.encode('utf-8')

        # 3. pass the payload bytes into this function
        try:
            req = urllib.request.Request(url, data=json_payload, headers=headers)
            response = urllib.request.urlopen(req, timeout=2)
            data = response.read()  # read the received bytes
            # load encoding if possible (default to utf-8)
            encoding = response.info().get_content_charset('utf-8')
            response.close()
        except urllib.error.HTTPError as error:
            print(error.read())
            exit()

        JSON_object = json.loads(data.decode(encoding))
        print(JSON_object)
        #return payload


    def tx_ping_check_EP(self, username, api_key, connection_address, connection_location,other_connections):
        url = "http://" + other_connections  + "/api/ping_check"

        # Credentials use server to update
        #username = "misl000"
        #password = "misl000_171902940"

        # current public key
        #pubkey = "c852f14e5c063da1dbedb7fa0d6cc9e4d6f61e581140b4ae2f46cddd67556d48"

        # connections
        connection_address = connection_address
        connection_location = connection_location
        my_time = str(time.time())

        # create HTTP BASIC authorization header
        #credentials = ('%s:%s' % (username, password))
        #b64_credentials = base64.b64encode(creden
        # tials.encode('ascii'))
        headers = {
            #'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'X-username': username,
            'X-apikey': api_key,
            'Content-Type': 'application/json; charset=utf-8',

            
        }

        payload = {

            "my_time": my_time,
            "connection_address": connection_address,
            "connection_location": connection_location,


        }

        
        # 1. convert the payload into json representation,
        payload_str = json.dumps(payload)

        # 2. ensure the payload is in bytes, not a string
        json_payload = payload_str.encode('utf-8')

        # 3. pass the payload bytes into this function
        try:
            req = urllib.request.Request(url, data=json_payload, headers=headers)
            response = urllib.request.urlopen(req, timeout=0.01)
            data = response.read()  # read the received bytes
            # load encoding if possible (default to utf-8)
            encoding = response.info().get_content_charset('utf-8')
            response.close()
        except urllib.error.HTTPError as error:
            print(error.read())
            exit()

        JSON_object = json.loads(data.decode(encoding))
        #print(status)
        print(JSON_object)

    def tx_groupmessage(self,username,apikey,loginserver_record,privatekey,group_message,connections):
        url = "http://" + connections + "/api/rx_groupmessage"
        #url = "http://" + connections + "/api/groupinvite"
        print("XXXXXXXXXXXXXXXXX")
        print(connections)
        print("XXXXXXXXXXXXXXXXX")

        ## LOGIN RECORD DONE

        #MAKE GROUPKEY HASH

        #ENCRYPTED GROUPKEY

        # timestamp
        sender_created_at = str(time.time())

        # target details
        key_password = "ikea"
        salt_password = bytes((key_password * 16).encode('utf-8')[:16])
        key_password_b = bytes(key_password, encoding='utf-8')
        print(key_password_b)
        print(salt_password)
        ops = nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE
        mems = nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE

        #symmetric_key = nacl.pwhash.argon2i.kdf(32,key_password_b,salt_password,ops,mems, encoder=nacl.encoding.HexEncoder)
        symmetric_key = nacl.pwhash.argon2i.kdf(32,key_password_b,salt_password,ops,mems)
        print(key_password)
        print(key_password_b)
        print(salt_password)
        print(ops)
        print(mems)
        print(symmetric_key)
        box = nacl.secret.SecretBox(symmetric_key)
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
        #message = Api.get_privatedata(self,username,api_key)
        groupkey_hash = nacl.hash.sha256(symmetric_key, encoder=nacl.encoding.HexEncoder).decode('utf-8')
        print(groupkey_hash)



        # Create signing key from private key
        signing_key = nacl.signing.SigningKey(privatekey, encoder=nacl.encoding.HexEncoder)
        sender_created_at = str(time.time())
        
        #publicKey,signaturePing_str,signature_str,signing_key,login = add_pubkey.PublicKey.add_key(self,username,password)
        
        # Sign message (login,targetkey,targetusernmae,encryptedmessage,sender_created_at)  
        group_msg = bytes(group_message, encoding='utf-8') 
        #privatedata = base64.b64encode(privatedata

        # Encrypt the private data
        encrypted_groupmessage = box.encrypt(group_msg,nonce, encoder=nacl.encoding.Base64Encoder).decode('utf-8')
        
        
        # Make signing key
        signing_key = nacl.signing.SigningKey(privatekey, encoder=nacl.encoding.HexEncoder)
        
        # Signing message
        signatureMessage = bytes(loginserver_record + encrypted_groupmessage + sender_created_at, encoding = 'utf-8')
        signedMessage = signing_key.sign(signatureMessage, encoder=nacl.encoding.HexEncoder)
        signature_str = signedMessage.signature.decode('utf-8')
        

        # create HTTP BASIC authorization header
        #credentials = ('%s:%s' % (username, password))
        #b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'X-username': username,
            'X-apikey': apikey,
            'Content-Type': 'application/json; charset=utf-8',
        }

        payload = {
            "loginserver_record":loginserver_record,
            "groupkey_hash": groupkey_hash,
            "group_message":encrypted_groupmessage,
            "sender_created_at":sender_created_at,
            "signature": signature_str,
        
        }
        print("HHHHHHHHHHHHHHHHHHHHHHHHHHH")
        print(payload)
        print("HHHHHHHHHHHHHHHHHHHHHHHHHHH")
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

    
    def tx_ping_check(self,username,api_key):
        all_connections = data.data.get_all_connections(self)
        personal_record = data.data.get_user_record(self,username)

        for i in range(len(all_connections["connections"])):
            try:
                Api.Api.tx_ping_check_EP(self,username,api_key,personal_record["user_connection_address"],personal_record["user_connection_location"],all_connections["connections"][i])
            except:
                print("No such connection exists")
        


       