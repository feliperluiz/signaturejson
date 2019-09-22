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

    print('2- Tempo ao chegar do Cliente')
    print(datetime.now())
    
    jsonData = request.json;
    hash_to_sign = jsonData['hash']
    pin = jsonData['pin']
    hash_signed = ''

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

    input_file = open("teste_sign.xml", "r")
    content = '';
    linechange = "<Data type=\"ByteString\" value=\""+hash_to_sign+"\" />"
    linechangePass = "<Password type=\"TextString\" value=\""+pin+"\" />"

    for line in input_file:
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

    input_file.close()
    output_file = open("teste_sign.xml", "w")
    output_file.write(content)
    output_file.close()
    
    xml2 = XML_runner(hsm1, "teste_sign.xml", idStore)
    hash_signed = xml2.init_test()
    print('5- Tempo ao retornar o hash ao navegador')
    print(datetime.now())
    hsm1.disconnect()
    return hash_signed
    # exit()

def main():
    app.run(port=5000, ssl_context=('server.crt', 'server.key'))
		
if __name__ == "__main__":
    main()