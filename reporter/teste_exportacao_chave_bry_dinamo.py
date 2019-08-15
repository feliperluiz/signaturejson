from kmiper.kmiper import *
import sys
import binascii
from datetime import datetime, timedelta
from kmiper_class_3 import Kmiper
from xml_runner_clazz import XML_runner
from flask import Flask, request
from flask_cors import CORS, cross_origin
import json
import re
import fileinput

app = Flask(__name__)
CORS(app)
@app.route('/sign', methods = ['POST'])
def postdata():
    hash_to_sign = request.get_data()
    print(hash_to_sign.decode('utf-8'))
#    hash_signed = "856eef7791b5947f2c67df1d72fb63415afe85d496ac7d6cb2e778f6df93f1f2783cb5c7f4114c479e13a0ddfaee08bfd33c30b78e6ff64b5df0e985b321452b7c09a0700e3a80e8037e3001ccdd3e2fef936fffed18639fcfb5d2b18fd1bd6cb3c763559f7551d6d6792ca82f476e37aeed40fb641b4a15c6eaadc1d8e7a20e383b7ed096bb6df129067283cf523aea481ef325f76206170a6ad6bd72726913962d6c4459460ed62e4dee3a5975f34352277b1fabfb85ef867047368ee59f8e862d60f2f0497a439b855e8b8d20b606cf7d83938e898957ee7cdbc5c0d3bdcc9b5e1da58fb971f735bad4deba4b9db451801e95016e29fd1af4b964c14d5a6d"
# cd C:/Users/Felipe/Desktop/TCC/signaturepython/reporter
    idStore = {}
    keyfile_hsm1 = "keyfelipe.pem"
    certfile_hsm1 = "certfelipe.pem"
    hsm_address1 = "dinamoxp.bry.com.br"
    cacert_hsm1 = "certificado_hsm.pem"
    port_hsm1 = 5696
    hsm1 = Kmiper(hsm_address1, port_hsm1, keyfile_hsm1, certfile_hsm1, cacert_hsm1, "#######   HSM 1 - Dinamo  ########") #Dinamo
	#hsm2 = Kmiper(hsm_address1, port_hsm1, keyfile_hsm1, certfile_hsm1, cacert_hsm1, "#######   HSM 2 - Dinamo  ########") #Dinamo
	# 01020304050607080910111213141516
	# 856eef7791b5947f2c67df1d72fb63415afe85d496ac7d6cb2e778f6df93f1f2783cb5c7f4114c479e13a0ddfaee08bfd33c30b78e6ff64b5df0e985b321452b7c09a0700e3a80e8037e3001ccdd3e2fef936fffed18639fcfb5d2b18fd1bd6cb3c763559f7551d6d6792ca82f476e37aeed40fb641b4a15c6eaadc1d8e7a20e383b7ed096bb6df129067283cf523aea481ef325f76206170a6ad6bd72726913962d6c4459460ed62e4dee3a5975f34352277b1fabfb85ef867047368ee59f8e862d60f2f0497a439b855e8b8d20b606cf7d83938e898957ee7cdbc5c0d3bdcc9b5e1da58fb971f735bad4deba4b9db451801e95016e29fd1af4b964c14d5a6d
    if(hsm1.connect() != True):
	    exit()

    input_file = open("ktc_export_keys_hsm2_password.xml", "r")
    content = '';
    match = 0

    linechange = "<Data type=\"ByteString\" value=\""+hash_to_sign.decode('utf-8')+"\" />"
    for line in input_file:
        match_hash = re.sub(r'<Data type=\"ByteString\" value=\"(.*)\" />', linechange, line) # should be your regular expression
        content += ''.join(match_hash)       
    
    input_file.close()

    output_file = open("ktc_export_keys_hsm2_password.xml", "w")
    output_file.write(content)

    #xml2 = XML_runner(hsm1, file_export_keys_hsm2, idStore)
    #xml2.init_test()
    
    hsm1.disconnect()
    exit()

    return hash_signed

def main():
	app.run(port=5000)
		
if __name__ == "__main__":
	main()