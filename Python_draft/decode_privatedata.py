import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time
import nacl.secret
import nacl.utils
import get_privatedata
class private_data(object):

   
    #def get_ping(self,username,password):
    #def authenticate(self,username,password):


        #STUDENT TO UPDATE THESE...
        self = "name"
        key = b'\x83\xebug\x86\x8d\x9b#\xfdRqY\xe7\xf6\x01$\x844\x9a+\xaf\x08O\xf7O\xd9\xe3;\xd2\xdc`\xf5'
        message = get_privatedata.private.get_encoded_data(self)
        box = nacl.secret.SecretBox(key)
        plaintext = box.decrypt(message,nonce=None, encoder=nacl.encoding.HexEncoder)
        print(str(plaintext))
 