"""
APP example that creates a symmtric key with the name as the app name. It connects with server over unix socket. 
"""

from __future__ import print_function

#Kmip client API
from kkmip import client
from kkmip import enums
from kkmip import types
from kkmip.error import KmipError

#Geeral
import os
import sys
import time

def create_symm_key(label, size, clt):
	"""
        Creates on kmip server a activated symmetric key (AES). 
        
        Args:
            label (unicode): name of the created key (unique on kmip server)
            size(int): size bits of the key (128, 192 or 256)
            clt(Client): Client object for requesting on kmip server

        Returns:
           Status of operation(bool): Two possible situations:
            1) True: The key has been created
            2) False: Problem occured 
	"""
	#Create attributes
	name_a = types.Attribute("Name", 0, types.Name(unicode(label), enums.NameType.UninterpretedTextString))
	algo_a = types.Attribute("Cryptographic Algorithm", 0, enums.CryptographicAlgorithm.AES)
	length_a = types.Attribute("Cryptographic Length", 0, size)
	usage_a = types.Attribute("Cryptographic Usage Mask", 0, enums.CryptographicUsageMask.Encrypt.value | enums.CryptographicUsageMask.Decrypt.value)
	
	#Create cryptographic parameters for attribute
	crypt_param = types.CryptographicParameters()
	crypt_param.block_cipher_mode = enums.BlockCipherMode.CBC
	crypt_param.padding_method = enums.PaddingMethod.PKCS5
	crypt_param.hashing_algorithm = enums.HashingAlgorithm.SHA_1
	crypt_param.random_iv = True #generate IV randomly

	#Create attribute for crypto parameters
	param_a = types.Attribute("Cryptographic Parameters", 0, crypt_param)

	#Create attribute template with above attr
	att_template = types.TemplateAttribute(None, [name_a, algo_a, length_a, usage_a,  param_a])

	#Create payload
	payload = types.CreateRequestPayload()
	payload.object_type = enums.ObjectType.SymmetricKey
	payload.template_attribute = att_template
	b = client.Batch(payload)

        #Send to kmip server
	try:    
		r = clt.post_batch(b)
	except Exception as e:
    		print(e)
		return False
	
	if isinstance(r[0], KmipError):
		print(r[0])
		return False
	else:
		return True


if __name__ == '__main__':
    #Unix communication
    clt = client.Client(None, None, client.Protocol.UNIX_JSON, False, None)

    #Create symmetric key with size
    print(create_symm_key(unicode("example_create_app.py"), 256, clt))
