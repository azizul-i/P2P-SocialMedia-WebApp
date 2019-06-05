import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time

class Checkkey(object):

        # endpoint and credentials
        url = "http://cs302.kiwi.land/api/list_users"
        username = "misl000"
        password = "misl000_171902940"



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
        #print(JSON_object)
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
            online_records.append(users[record])
            username.append(users[record]["username"])
            connection_address.append(users[record]["connection_address"])
            connection_location.append(users[record]["connection_location"])
            updated_time.append(users[record]["connection_updated_at"])
            publickey.append(users[record]["incoming_pubkey"])
            status.append(users[record]["status"])

        print(username)
        print(status)
        print(online_records)
        for i in range(len(username)):
            print(username[i])
        #for first in JSON_object.items():
            #print(first)
            #for second in JSON_object[first].keys():
                #print(second)
        #print(JSON_object[first])
