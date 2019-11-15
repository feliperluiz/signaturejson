from kmiper.kmiper import *
import sys
import binascii
import json
import re
import fileinput
from datetime import datetime, timedelta
from kmiper_class_3 import Kmiper
from xml_runner_clazz import XML_runner
from flask import Flask, request
from flask_cors import CORS, cross_origin

app = Flask(__name__)
CORS(app)
@app.route('/sign', methods = ['POST'])
def postdata():    
    jsonData = request.json;
    hash_to_sign = jsonData['hash']
    pin = jsonData['pin']
    linechange = "<Data type=\"ByteString\" value=\""+hash_to_sign+"\" />"
    linechangePass = "<Password type=\"TextString\" value=\""+pin+"\" />"

    idStore = {}
    keyfile_hsm1 = "keyfelipe.pem"
    certfile_hsm1 = "certfelipe.pem"
    hsm_address1 = "dinamoxp.bry.com.br"
    cacert_hsm1 = "certificado_hsm.pem"
    port_hsm1 = 5696
    hsm1 = Kmiper(hsm_address1, port_hsm1, keyfile_hsm1, certfile_hsm1, cacert_hsm1, "#######   HSM 1 - Dinamo  ########") #Dinamo

    if(hsm1.connect() != True):
	    exit()

    sign_file = open("teste_sign.xml", "r")
    content = '';

    for line in sign_file:
        match1 = re.compile(r'<Data type=\"ByteString\" value=\"(.*)\" />') # should be your regular expression
        mo1 = match1.search(line)

        match2 = re.compile(r'<Password type=\"TextString\" value=\"(.*)\" />')
        mo2 = match2.search(line)
        
        if mo1 is not None:
            match = re.sub(r'<Data type=\"ByteString\" value=\"(.*)\" />', linechange, line)
            content += ''.join(match)
        elif mo2 is not None:
            match = re.sub(r'<Password type=\"TextString\" value=\"(.*)\" />', linechangePass, line)
            content += ''.join(match)
        else:
            content += ''.join(line)

    sign_file.close()
    output_file_sign = open("teste_sign.xml", "w")
    output_file_sign.write(content)
    output_file_sign.close()

    xml1 = XML_runner(hsm1, "teste_sign.xml", idStore)
    hash_signed = xml1.init_test()
    linechangeSignature = "<SignatureData type=\"ByteString\" value=\""+hash_signed+"\" />"
    verify_file = open("teste_verify.xml", "r")
    content = '';
    
    for line in verify_file:
        match1 = re.compile(r'<SignatureData type=\"ByteString\" value=\"(.*)\" />')
        mo1 = match1.search(line)

        match2 = re.compile(r'<Data type=\"ByteString\" value=\"(.*)\" />')
        mo2 = match2.search(line)

        match3 = re.compile(r'<Password type=\"TextString\" value=\"(.*)\" />')
        mo3 = match3.search(line)

        if mo1 is not None:
            match = re.sub(r'<SignatureData type=\"ByteString\" value=\"(.*)\" />', linechangeSignature, line)
            content += ''.join(match)
        elif mo2 is not None:
            match = re.sub(r'<Data type=\"ByteString\" value=\"(.*)\" />', linechange, line)
            content += ''.join(match)
        elif mo3 is not None:
            match = re.sub(r'<Password type=\"TextString\" value=\"(.*)\" />', linechangePass, line)
            content += ''.join(match)
        else:
            content += ''.join(line)

    verify_file.close()
    output_file_verify = open("teste_verify.xml", "w")
    output_file_verify.write(content)
    output_file_verify.close()

    xml2 = XML_runner(hsm1, "teste_verify.xml", idStore)
    is_valid = xml2.init_test()
    hsm1.disconnect()

    data = {}
    data['signature'] = hash_signed
    data['valid'] = is_valid
    json_final = json.dumps(data)
    return json_final

def main():
    app.run(host= 'Felipe', port=5000, ssl_context=('server.crt', 'server.key'))
		
if __name__ == "__main__":
    main()