"""
The client module is responsible for sending requests to a KMIP server.
"""
from __future__ import (print_function, division, unicode_literals, absolute_import)

import enum
import json
import socket
import ssl
import warnings

import requests
from os import path

from kkmip import conn
from kkmip import enums
from kkmip import ttv
from kkmip import types
from kkmip.error import KmipError

DEFAULT_VERSION = (1, 3)
"""
tuple(int, int): the default KMIP version used by the client.
"""


class Protocol(enum.Enum):
    """
    KMIP protocol enumeration.
    """
    TTLV = 1 #: Raw TTLV protocol. Binary format, smaller size.
    HTTPS_TTLV = 2 #: TTLV over HTTPS.
    HTTPS_JSON = 3 #: JSON over HTTPS.
    HTTPS_XML = 4 #: XML over HTTPS.
    # TODO: XXX: Kryptus-specific code. Remove if open-source
    UNIX_TTLV = 11
    UNIX_JSON = 10
    UNIX_XML = 12


def _check_http_response(r):
    """
    Check the HTTP response and raise an error accordingly.

    Args:
        r: the response from requests.post

    Raises:
        RuntimeError: on any HTTP error.
    """
    if not 200 <= r.status_code < 300:
        raise RuntimeError('Error posting request: {}'.format(r.status_code))


class Client(object):
    """
    A client for a KMIP server.

    Args:
        host (str): the hostname or IP of the server
        port (int): the port of the server
        protocol (Protocol): the protocol used to communicate with the KMIP server
        verify (bool or str): if the server certificate is validated (bool); the path
            of the trusted CA certificate (str); or path of the folder with trusted CA
            certificates generated using c_rehash from OpenSSL (str).
        cert (str or (str, str)): path to the client key/certificate bundle or tuple with the
            path of the client certificate and of the client key.
        version (tuple(int, int)): the KMIP version to use.
    """

    def __init__(self, host=None, port=5696, protocol=Protocol.TTLV, verify=True, cert=None,
                 version=DEFAULT_VERSION):
        self.host = host
        self.port = port
        self.protocol = protocol
        self.version = version
        self.is_https = False
        if protocol.name.startswith('HTTPS'):
            self.is_https = True
            # Using a Session allows connection reuse
            self.conn = requests.Session()
            self.conn.headers.update({'Cache-Control': 'no-cache'})
            self.conn.verify = verify
            self.conn.cert = cert
        elif protocol == Protocol.TTLV:
            self.ctx = ssl.create_default_context()
            # Replicating the Requests package handling of these arguments
            if not verify:
                self.ctx.check_hostname = False
                self.ctx.verify_mode = ssl.CERT_NONE
                warnings.warn('SSL verification disabled!')
            else:
                if path.isfile(verify):
                    self.ctx.load_verify_locations(cafile=verify)
                else:
                    self.ctx.load_verify_locations(capath=verify)
            if cert is not None:
                if isinstance(cert, (tuple, list)):
                    if cert[0] is not None and cert[1] is not None:
                        self.ctx.load_cert_chain(cert[0], cert[1])
                else:
                    self.ctx.load_cert_chain(cert)

    def post(self, payload):
        """
        Post a single request to the KMIP server.

        Args:
            payload (subclass of :class:`~.types.RequestPayload`): the request payload.

        Returns:
            The response (subclass of :class:`~.types.ResponsePayload`).

        Raises:
            :class:`~.error.KmipError` if the server returned an error.
        """
        b = Batch(payload)
        r = self.post_batch(b)[0]
        if isinstance(r, Exception):
            raise r
        return r

    def post_batch(self, batch):
        """
        Post a batch of requests to the KMIP server.

        Args:
            batch (Batch): the batch of requests

        Returns:
            List of response payloads (subclasses of ResponsePayload), one for each request,
            in order. If there was an error in the request, a KmipError will be present instead
            of the the response payload.
        """
        request = batch.create_request_message(version=self.version)
        response = self.post_request_message(request)

        def extract_payload_or_error(batch_item):
            """
            Return a KmipError if there was a error in the item, or the item payload otherwise.
            """
            if batch_item.result_status == enums.ResultStatus.Success:
                return batch_item.response_payload
            return KmipError(
                batch_item.result_status, batch_item.result_reason, batch_item.result_message
            )

        return [extract_payload_or_error(batch_item) for batch_item in response.batch_item_list]

    def post_request_message(self, request):
        """
        Post a Request Mesasge to the KMIP server.

        This a lower-level function; post and post_batch should be enough unless you wish to tweak
        the request.

        Args:
            request (types.RequestMessage): the KMIP request

        Returns:
            response (types.ResponseMessage): the KMIP response
        """
        ttv_request = request.encode()
        if self.protocol == Protocol.TTLV:
            raw_conn = socket.create_connection((self.host, self.port))
            self.conn = self.ctx.wrap_socket(raw_conn, server_hostname=self.host)
            try:
                ttlv_request = ttv_request.encode_ttlv()
                self.conn.sendall(ttlv_request)
                header = conn.recvall(self.conn, 8)
                size = ttv.decode_ttlv_header(header)[4]
                value = conn.recvall(self.conn, size)
                ttlv_response = header + value
                ttv_response = ttv.decode_ttlv(ttlv_response)
            finally:
                self.conn.close()
        elif self.is_https:
            if self.protocol == Protocol.HTTPS_JSON:
                json_request = ttv_request.encode_json()
                r = self.conn.post('https://{}:{}/kmip'.format(self.host, self.port),
                                   json=json_request)
                _check_http_response(r)
                json_response = r.json()
                ttv_response = ttv.decode_json(json_response)
            elif self.protocol == Protocol.HTTPS_XML:
                xml_request = ttv.encode_xml_to_string(ttv_request.encode_xml())
                r = self.conn.post('https://{}:{}/kmip'.format(self.host, self.port),
                                   data=xml_request,
                                   headers={'Content-Type': 'text/xml'})
                _check_http_response(r)
                xml_response = ttv.decode_xml_from_string(r.content)
                ttv_response = ttv.decode_xml(xml_response)
            elif self.protocol == Protocol.HTTPS_TTLV:
                ttlv_request = ttv_request.encode_ttlv()
                r = self.conn.post('https://{}:{}/kmip'.format(self.host, self.port),
                                   data=ttlv_request,
                                   headers={'Content-Type': 'application/octet-stream'})
                _check_http_response(r)
                ttlv_response = r.content
                ttv_response = ttv.decode_ttlv(ttlv_response)
            else:
                raise RuntimeError('Unsupported protocol: {}'.format(self.protocol))
        # TODO: XXX: Kryptus-specific code. Remove if open-source
        elif self.protocol == Protocol.UNIX_JSON:
            json_request = ttv_request.encode_json()
            raw_request = json.dumps(json_request).encode('utf8')
            raw_response = conn.send_request(raw_request, protocol=conn.JSON_PROTOCOL)
            json_response = json.loads(raw_response.decode('utf8'))
            ttv_response = ttv.decode_json(json_response)
        elif self.protocol == Protocol.UNIX_XML:
            xml_request = ttv.encode_xml_to_string(ttv_request.encode_xml())
            raw_response = conn.send_request(xml_request, protocol=conn.XML_PROTOCOL)
            xml_response = ttv.decode_xml_from_string(raw_response)
            ttv_response = ttv.decode_xml(xml_response)
        elif self.protocol == Protocol.UNIX_TTLV:
            ttlv_request = ttv_request.encode_ttlv()
            ttlv_response = conn.send_request(ttlv_request, protocol=conn.TTLV_PROTOCOL)
            ttv_response = ttv.decode_ttlv(ttlv_response)
        else:
            raise RuntimeError('Unsupported protocol: {}'.format(self.protocol))

        response = types.decode(ttv_response)
        return response


class Batch(object):
    """
    A batch of requests.

    KMIP handles batches of requests which are processed as a set, allowing using the ID placeholder.

    Args:
        request_payloads (subclasses of RequestPayload): the requests
    """

    def __init__(self, *request_payloads):
        self.payloads = list(request_payloads)

    def add(self, payload):
        """
        Add a request to the batch.

        Args:
            payload (subclass of :class:`.RequestPayload`): the request to add.
        """
        self.payloads.append(payload)

    def create_request_message(self, version=DEFAULT_VERSION):
        """
        Create a KMIP RequestMessage for this batch.

        Returns:
            RequestMessage for this batch.
        """
        return types.RequestMessage(
            types.RequestHeader(
                protocol_version=types.ProtocolVersion(version[0], version[1]),
                batch_count=len(self.payloads),
            ),
            [types.RequestBatchItem(operation=batch_item.OPERATION, request_payload=batch_item)
             for batch_item in self.payloads],
        )
