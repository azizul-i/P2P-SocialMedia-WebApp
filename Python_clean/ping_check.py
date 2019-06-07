import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time

class Serverkey(object):

        # endpoint and credentials
        url = "http://172.23.13.81:8080/api/ping_check"

        # Credentials use server to update
        username = "misl000"
        password = "misl000_171902940"

        # current public key
        #pubkey = "c852f14e5c063da1dbedb7fa0d6cc9e4d6f61e581140b4ae2f46cddd67556d48"

        # connections
        connection_address = "172.23.13.81:8080"
        connection_location = "2"
        my_time = str(time.time())

        # create HTTP BASIC authorization header
        credentials = ('%s:%s' % (username, password))
        b64_credentials = base64.b64encode(credentials.encode('ascii'))
        headers = {
            'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
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
            response = urllib.request.urlopen(req)
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
