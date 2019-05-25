import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time

class PublicKey(object):

    #def add_key(self,username,password):
        url = "http://cs302.kiwi.land/api/loginserver_pubkey"
        #STUDENT TO UPDATE THESE...
        username = "misl000"
        password = "misl000_171902940"
        publicKey = "57cb31eb221c714f1b88f5f8745dddc47a1bcfbb03faebf0814160fafe2d4e73"



        # create HTTP BASIC authorization header
        credentials = ('%s:%s' % (username, password))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
            'Content-Type': 'application/json; charset=utf-8',
            
        }

        payload = {
            "pubkey": publicKey
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
