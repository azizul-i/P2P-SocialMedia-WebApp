import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time
#import add_pubkey



class private_message(object):
    #def broadcasting(self,username,password,publicKey,signing_key):
        url = "http://cs302.kiwi.land/api/rx_privatemessage"
        username = "misl000"
        password = "misl000_171902940"
        target_username = "admin"
        sender_created_at = str(time.time())
        target_pubkey = "11c8c33b6052ad73a7a29e832e97e31f416dedb7c6731a6f456f83a344488ec0"
        target_key = nacl.signing.VerifyKey(target_pubkey,encoder=nacl.encoding.HexEncoder).to_curve25519_public_key()
        box = nacl.public.SealedBox(target_key)
        target_key_str = target_key.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')
        message = bytes("Testing out Private messaging",encoding = 'utf-8')
        encrypted_message = box.encrypt(message, encoder=nacl.encoding.HexEncoder).decode('utf-8')
        #self = "broadcast"
        #publicKey = ""
        signatureTemp = ""
        signature = ""
        publickey = "c852f14e5c063da1dbedb7fa0d6cc9e4d6f61e581140b4ae2f46cddd67556d48"
        privatekey = "2a4ec0f5a1edeca10c344b9d3558fb4cb411be6006c086252f3042a92434cf29"
        login = 'misl000,c852f14e5c063da1dbedb7fa0d6cc9e4d6f61e581140b4ae2f46cddd67556d48,1558689185.3489795,4625731f1a7396bcffad7b68da2c0de8fcc222663f8ac75bd88597ac4dfdaa2fced2d4e841e86f1d316bf9c010dd4e6bc005f70ee7558546e0d7b76a3af9ff01'
        signing_key = nacl.signing.SigningKey(privatekey, encoder=nacl.encoding.HexEncoder)
        sender_created_at = str(time.time())
        
        #publicKey,signaturePing_str,signature_str,signing_key,login = add_pubkey.PublicKey.add_key(self,username,password)
        signatureMessage = bytes(login + target_pubkey + target_username + encrypted_message + sender_created_at, encoding = 'utf-8')
        signedMessage = signing_key.sign(signatureMessage, encoder=nacl.encoding.HexEncoder)
        signature_str = signedMessage.signature.decode('utf-8')
        

        # create HTTP BASIC authorization header
        credentials = ('%s:%s' % (username, password))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'Content-Type': 'application/json; charset=utf-8',
        }

        payload = {
            "loginserver_record":login,
            "target_pubkey":target_pubkey,
            "target_username":target_username,
            "encrypted_message": encrypted_message,
            "sender_created_at" : sender_created_at,
            "signature": signature_str,
        

            # STUDENT TO COMPLETE THIS...
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



