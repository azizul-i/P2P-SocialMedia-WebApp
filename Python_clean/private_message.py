import urllib.request
import json
import base64
import nacl.encoding
import nacl.signing
import time
import Api
import Get_Loginserver_records
#import add_pubkey



class private_message(object):
    #def broadcasting(self,username,password,publicKey,signing_key):

        """ Use this API to transmit a secret message between users. Meta-information is
            public (the sender username/pubkey, and the destination username/pubkey, the timestamp). """
        url = "http://192.168.87.21:8080/api/rx_privatemessage"
        username = "misl000"
        password = "misl000_171902940"

        # timestamp
        sender_created_at = str(time.time())

        # target details
        target_username = "misl000"
        target_pubkey = "849bebfcfcf8c91bfae44088ceeac35e2b9c02db3727822e10df03ed2da25ba4"

        # Generate encrypting public key
        target_key = nacl.signing.VerifyKey(target_pubkey,encoder=nacl.encoding.HexEncoder).to_curve25519_public_key()

        # Make sealed box using public key (can only be decoded by target)
        box = nacl.public.SealedBox(target_key)

        target_key_str = target_key.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')

        # Private message that needs to be encrypted
        message = bytes("ALLOO",encoding = 'utf-8')
        encrypted_message = box.encrypt(message, encoder=nacl.encoding.HexEncoder).decode('utf-8')

        # Create signing key from private key
        publickey = "849bebfcfcf8c91bfae44088ceeac35e2b9c02db3727822e10df03ed2da25ba4"
        privatekey = "7333aec56f033a132a86a1e1187d9874e93050fab19ef441b1410533cb812281"
        login = Get_Loginserver_records.Serverkey.get_loginrecord("name")
        #'misl000,849bebfcfcf8c91bfae44088ceeac35e2b9c02db3727822e10df03ed2da25ba4,1558689185.3489795,4625731f1a7396bcffad7b68da2c0de8fcc222663f8ac75bd88597ac4dfdaa2fced2d4e841e86f1d316bf9c010dd4e6bc005f70ee7558546e0d7b76a3af9ff01'
        signing_key = nacl.signing.SigningKey(privatekey, encoder=nacl.encoding.HexEncoder)
        sender_created_at = str(time.time())
        
        #publicKey,signaturePing_str,signature_str,signing_key,login = add_pubkey.PublicKey.add_key(self,username,password)
        
        # Sign message (login,targetkey,targetusernmae,encryptedmessage,sender_created_at)
        signatureMessage = bytes(login + target_pubkey + target_username + encrypted_message + sender_created_at, encoding = 'utf-8')
        signedMessage = signing_key.sign(signatureMessage, encoder=nacl.encoding.HexEncoder)
        signature_str = signedMessage.signature.decode('utf-8')

        unseal_key = nacl.signing.SigningKey(privatekey,encoder=nacl.encoding.HexEncoder).to_curve25519_private_key()
        unseal_box = nacl.public.SealedBox(unseal_key)
        plain_text = unseal_box.decrypt(encrypted_message, encoder=nacl.encoding.HexEncoder).decode('utf-8')
        print(plain_text)

        

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



