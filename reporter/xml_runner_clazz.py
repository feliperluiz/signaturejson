import sys
import binascii
import socket
import ssl
import re
from datetime import datetime, timedelta
from kmiper_class_3 import Kmiper
from enum import Enum
from kkmip import ttv
from kkmip import types
from xml.etree import ElementTree
from xml.dom import minidom

class TipoMSG(Enum):
		REQUEST = 1
		RESPONSE = 2
		
class XML_runner():
	hsm = None
	xmlfile = None
	idStore = {}
	
	def __init__(self, hsm, xmlfile, idStore):	
		self.hsm = hsm
		self.xmlfile = xmlfile
		self.idStore = idStore
		
	def writeToFile(self, xmlString, path, filename):
		with open(path + filename, "a") as f:
			f.write(xmlString)
		
	def parse_xml_timestamp(self, xml_node):
		if "value" in xml_node.attrib:
			if "$NOW-3600" in xml_node.attrib['value']:
				xml_node.attrib['value'] = (datetime.utcnow() - timedelta(seconds=3600)).isoformat()
			elif "$NOW" in xml_node.attrib['value']:
				xml_node.attrib['value'] = datetime.utcnow().isoformat()
		for e in xml_node:
			self.parse_xml_timestamp(e)
	
	def parse_tag(self, xml_node, idStore, tipoMsg, tag, value):
		if tag in xml_node.tag.lower():
			if tipoMsg == TipoMSG.REQUEST:
				if "keyvalue" in tag:
					if 'value' in xml_node.attrib:
						xml_node.attrib['value'] = idStore[xml_node.attrib['value']]
				else:
					if xml_node.attrib['value'] in idStore:
						xml_node.attrib['value'] = idStore[xml_node.attrib['value']]
					else:
						xml_node.attrib['value'] = xml_node.attrib['value']
			else:
				if "keyvalue" in tag:
					if 'value' in xml_node.attrib:
						if value in xml_node.attrib['value']:
							idStore[xml_node.tag] = xml_node.attrib['value']
						else:
							uid_str = idStore[xml_node.tag]
							idStore[uid_str] = xml_node.attrib['value']
				else:			
					if value in xml_node.attrib['value']:
						idStore[xml_node.tag] = xml_node.attrib['value']
					else:
						if xml_node.tag != "UniqueIdentifier":
							uid_str = idStore[xml_node.tag]
							idStore[uid_str] = xml_node.attrib['value']
						else:
							return
		for e in xml_node:
			self.parse_tag(e, idStore, tipoMsg, tag, value)
	
	def parse_uid(self, xml_node, idStore, tipoMsg):
		self.parse_tag(xml_node, idStore, tipoMsg, "uniqueid", "UID")
			
	def parse_modulus(self, xml_node, idStore, tipoMsg):
		self.parse_tag(xml_node, idStore, tipoMsg, "modulus", "MODULUS")
					
	def parse_pub_exponent(self, xml_node, idStore, tipoMsg):
		self.parse_tag(xml_node, idStore, tipoMsg, "publicexponent", "EXPONENT")
					
	def parse_key_value(self, xml_node, idStore, tipoMsg):
		self.parse_tag(xml_node, idStore, tipoMsg, "keyvalue", "VALUE")
		
	def parse_iv_value(self, xml_node, idStore, tipoMsg):
		self.parse_tag(xml_node, idStore, tipoMsg, "ivcounternonce", "IV")
					
	def init_test(self):
		with open(self.xmlfile, 'r') as file:
			file_data = file.read().replace('\n', '').replace('\t','')
			
		testcase = ElementTree.fromstring(file_data)
		for i in range(0,len(testcase), 2):
			ereq = testcase[i]
			eres = testcase[i+1]

			self.parse_xml_timestamp(ereq)
			self.parse_uid(ereq, self.idStore, TipoMSG.REQUEST)
			self.parse_modulus(ereq, self.idStore, TipoMSG.REQUEST)
			self.parse_pub_exponent(ereq, self.idStore, TipoMSG.REQUEST)
			self.parse_key_value(ereq, self.idStore, TipoMSG.REQUEST)
			self.parse_iv_value(ereq, self.idStore, TipoMSG.REQUEST)

			ttlv = self.hsm.parse_xml_to_ttlv_bytes(ereq)		
			received = self.hsm.send_receive(ttlv)			
			response = self.hsm.parse_ttlv_bytes_to_xml_tree(received)
			responseWithSign = self.hsm.parse_xml_to_pretty_string(response)
			matchSign = re.search(r'<SignatureData type=\"ByteString\" value=\"(.*?)\"/>', responseWithSign)			
			matchValid = re.search(r'<ValidityIndicator type=\"Enumeration\" value=\"(.*?)\"/>', responseWithSign)			

			if matchSign:
				return matchSign.group(1)
			elif matchValid:
				if matchValid.group(1) == 'Valid':
					return True
				else:
					return False

			self.parse_uid(eres, self.idStore, TipoMSG.RESPONSE)
			self.parse_uid(response, self.idStore, TipoMSG.RESPONSE)
			self.parse_xml_timestamp(response)
			
			self.parse_modulus(eres, self.idStore, TipoMSG.RESPONSE)
			self.parse_modulus(response, self.idStore, TipoMSG.RESPONSE)
			
			self.parse_pub_exponent(eres, self.idStore, TipoMSG.RESPONSE)
			self.parse_pub_exponent(response, self.idStore, TipoMSG.RESPONSE)
			
			self.parse_key_value(eres, self.idStore, TipoMSG.RESPONSE)
			self.parse_key_value(response, self.idStore, TipoMSG.RESPONSE)
			
			self.parse_iv_value(eres, self.idStore, TipoMSG.RESPONSE)
			self.parse_iv_value(response, self.idStore, TipoMSG.RESPONSE)