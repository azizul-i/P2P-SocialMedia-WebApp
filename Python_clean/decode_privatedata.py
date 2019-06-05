import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time
import nacl.secret
import nacl.utils
import get_privatedata
import nacl.pwhash

class private_data(object):
    # Prints decoded private data
    def decodeKeys(self):

        # ask hammond about self
        self = "private_data"

        # SecretBox Key
        key_password = str(1234)
        salt = key_password * 16
        salt_password = bytes(salt.encode('utf-8')[:16])
        key_password_b = bytes(key_password, encoding='utf-8')
        ops = nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE
        mems = nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE
        #symmetric_key = nacl.pwhash.argon2i.kdf(32,key_password_b,salt_password,ops,mems, encoder=nacl.encoding.HexEncoder)
        symmetric_key = nacl.pwhash.argon2i.kdf(32,key_password_b,salt_password,ops,mems)
        print(symmetric_key)
        message = get_privatedata.private.get_encoded_data(self)
        box = nacl.secret.SecretBox(symmetric_key)
        plaintext = box.decrypt(message,nonce=None, encoder=nacl.encoding.HexEncoder)
        print(str(plaintext))
        tmp = json.loads((plaintext))
        #tmp_dict = dict(tmp)
        #p_keys = ','.join(map(str,tmp["prikeys"]))
        p_keys = (tmp["prikeys"])
        p_keys = str(p_keys[0])
        print(p_keys)
        return str(p_keys)

 