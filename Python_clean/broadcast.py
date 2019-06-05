import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time
import Get_Loginserver_records
import decode_privatedata



class Broadcast_message(object):
    #def broadcasting(self,username,password,message):

        """Use this API to transmit a signed broadcast between users. You need to be
           authenticated, and the broadcast public key must be known, but the broadcast public key
           need not be associated to your account."""

        url = "http://cs302.kiwi.land/api/rx_broadcast"
        username = "misl000"
        password = "misl000_171902940"
        message = "Test 4305"
        self = "broadcast"

        # Load public and private keys
        #publickey = "c852f14e5c063da1dbedb7fa0d6cc9e4d6f61e581140b4ae2f46cddd67556d48"
        privatekey = decode_privatedata.private_data.decodeKeys(self)

        # Load login record
        login = Get_Loginserver_records.Serverkey.get_loginrecord(self,username,password) # Get login record works
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
        signatureMessage = bytes(login + message + sender_created_at, encoding = 'utf-8')
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



