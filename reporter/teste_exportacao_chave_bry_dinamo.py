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
    hash_signed = ''

    print('Hash que será assinado: ' + hash_to_sign.decode('utf-8'))
    
    # cd C:/Users/Felipe/Desktop/TCC/signaturepython/reporter
    idStore = {}
    keyfile_hsm1 = "keyfelipe.pem"
    certfile_hsm1 = "certfelipe.pem"
    hsm_address1 = "dinamoxp.bry.com.br"
    cacert_hsm1 = "certificado_hsm.pem"
    port_hsm1 = 5696
    hsm1 = Kmiper(hsm_address1, port_hsm1, keyfile_hsm1, certfile_hsm1, cacert_hsm1, "#######   HSM 1 - Dinamo  ########") #Dinamo

    if(hsm1.connect() != True):
	    exit()

    input_file = open("ktc_export_keys_hsm2_password.xml", "r")
    content = '';
    linechange = "<Data type=\"ByteString\" value=\""+hash_to_sign.decode('utf-8')+"\" />"
    for line in input_file:
        match_hash = re.sub(r'<Data type=\"ByteString\" value=\"(.*)\" />', linechange, line) # should be your regular expression
        content += ''.join(match_hash)       
    
    input_file.close()
    output_file = open("ktc_export_keys_hsm2_password.xml", "w")
    output_file.write(content)
    output_file.close()
    
    xml2 = XML_runner(hsm1, "ktc_export_keys_hsm2_password.xml", idStore)
    hash_signed = xml2.init_test()
    
    hsm1.disconnect()
    return hash_signed
    # exit()

def main():
	app.run(port=5000)
		
if __name__ == "__main__":
	main()