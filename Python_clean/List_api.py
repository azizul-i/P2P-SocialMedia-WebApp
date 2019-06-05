import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time

class list_api(object):
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
        #p = ','.join(map(str,JSON_object)
        print(JSON_object) 
        for key in JSON_object.keys():
            print(key)
            print(JSON_object[key])