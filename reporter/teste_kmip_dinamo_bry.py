from kmiper.kmiper import *
import sys
import binascii
from datetime import datetime, timedelta
from kmiper_class_3 import Kmiper
from xml_runner_class import XML_runner
		

def main():
	"""
	In development! Here be dragons!
	using OASIS profile XML notation, root node is <kmip>
	followed by child pairs <requestmessage> and <responsemessage>
	in this order. Must not change.
	"""
	
	idStore = {}

	#hsm_address2 = "kryptus.dyndns.biz"
	#keyfile_hsm2 = "kryptus/vHSM_3/user1.key"
	#certfile_hsm2 = "kryptus/vHSM_3/user1.crt"
	#port_hsm2 = 49172
	
	#keyfile_hsm2 = "kryptus/vHSM_5/user1.key"
	#certfile_hsm2 = "kryptus/vHSM_5/user1.crt"
	#port_hsm2 = 49192  #Kryptus 2
	
	
	keyfile_hsm1 = "Dinamo_Test/lab.pri"
	certfile_hsm1 = "Dinamo_Test/lab.cer"
	
	#port_hsm1 = 5696

	#cacert_hsm1 = "Dinamo_Test/hsm.cer"

	hsm_address1 = "200.202.34.21"

	#hsm_address1 = "192.168.105.9"
	#keyfile_hsm1 = "Dinamo_Test/private_key.pem"
	#certfile_hsm1 = "Dinamo_Test/lab.cer"
	#cacert_hsm1 = "Dinamo_Test/certificado_hsm.pem"
	cacert_hsm1 = "Dinamo_Test/hsm.cer"
	port_hsm1 = 5696
	hsm1 = Kmiper(hsm_address1, port_hsm1, keyfile_hsm1, certfile_hsm1, cacert_hsm1, "#######   HSM 2 - Dinamo  ########") #Dinamo





	
	#hsm2 = Kmiper(hsm_address2, port_hsm2, keyfile_hsm2, certfile_hsm2, "#######   HSM 2 - Kryptus  ########") #Kryptus
	#hsm1 = Kmiper(hsm_address1, port_hsm1, "#######   HSM 1 - Dinamo  ########") #Dinamo

	
	
	#hsm2 = Kmiper(hsm_address, port_hsm2, keyfile_hsm2, certfile_hsm2, "#######   HSM 2  ########") #Kryptus
	#HSM1 - Importer
	if(hsm1.connect() != True):
		exit()
	
	file_export_pub_key_hsm1 = "testcases/teste_dinamo_bry_5.xml"
	#file_export_pub_key_hsm1 = "testcases/ktc/ktc_export_public_key_hsm1_password_with_pub_id.xml"
	#file_export_pub_key_hsm1 = "testcases/ktc/ktc_export_public_key_hsm1.xml"
	xml1 = XML_runner(hsm1, file_export_pub_key_hsm1, idStore)
	xml1.init_test()
	
	#HSM2 - Exporter
	
	#if(hsm2.connect() != True):
	#	exit()
		
	#file_export_keys_hsm2 = "testcases/ktc/ktc_export_keys_hsm2_password2.xml"
	#file_export_keys_hsm2 = "testcases/ktc/ktc_export_keys_hsm2_password.xml"
	#file_export_keys_hsm2 = "testcases/ktc/ktc_export_keys_hsm2.xml"
	#xml2 = XML_runner(hsm2, file_export_keys_hsm2, idStore)
	#xml2.init_test()
	
	#HSM1 - Importer
	
	#file_imported_exported_keys_hsm1 = "testcases/ktc/ktc_import_exported_keys_hsm1.xml"
	#file_imported_exported_keys_hsm1 = "testcases/ktc/ktc_import_exported_keys_hsm1_2.xml"
	#file_imported_exported_keys_hsm1 = "testcases/ktc/ktc_import_exported_keys_hsm1_2_password_with_priv_id.xml"
	#file_imported_exported_keys_hsm1 = "testcases/ktc/ktc_import_exported_keys_hsm1_2_password.xml"
	#xml3 = XML_runner(hsm1, file_imported_exported_keys_hsm1, idStore)
	#xml3.init_test()
	
	#CleanUp
	#file_cleanup_hsm1 = "testcases/ktc/ktc_clean_up_hsm1_2_password.xml"
	#file_cleanup_hsm1 = "testcases/ktc/ktc_clean_up_hsm1_2.xml"
	#file_cleanup_hsm1 = "testcases/ktc/ktc_clean_up_hsm1.xml"
	#xml4 = XML_runner(hsm1, file_cleanup_hsm1, idStore)
	#xml4.init_test()
	
	#file_cleanup_hsm2 = "testcases/ktc/ktc_clean_up_hsm2_password2.xml"
	#file_cleanup_hsm2 = "testcases/ktc/ktc_clean_up_hsm2_password.xml"
	#file_cleanup_hsm2 = "testcases/ktc/ktc_clean_up_hsm2.xml"
	#xml5 = XML_runner(hsm2, file_cleanup_hsm2, idStore)
	#xml5.init_test()

	#Disconnecting
	hsm1.disconnect()
	#hsm2.disconnect()
	
	exit()
	
if __name__ == "__main__":
	main()
