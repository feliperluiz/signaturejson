"""
Implements IPC communication between the APP and its KMIP server.

Uses a custom binary protocol.

"""

import os
import socket
import struct

_KMIP_SOCKET_DIR = 'socket'
_KMIP_SOCKET_FILE = "kmip-server.socket"

# Convert protocols to its string representation
TTLV_PROTOCOL = b'\x00'
XML_PROTOCOL = b'\x01'
JSON_PROTOCOL = b'\x02'

_protocols = [TTLV_PROTOCOL, XML_PROTOCOL, JSON_PROTOCOL]


def recvall(sock, count):
    """
    Receive the specified amount of bytes from a socket.

    Args:
        sock (socket.socket): the socket
        count (int): number of bytes to read.

    Returns:
        bytes: the data read.
    """
    buf = bytearray(count)
    bufv = memoryview(buf)
    nread = 0
    while nread < count:
        nread += sock.recv_into(bufv[nread:])
    return buf


class InvalidProtocolError(Exception):
    """ Error return when an invalid protocol is received """

    def __init__(self, protocol):
        self.protocol = protocol

    def __str__(self):
        return 'Invalid value for protocol: {}'.format(self.protocol)


class ResponseProtocolError(Exception):
    def __init__(self, reason):
        self.reason = reason

    def __str__(self):
        return 'Error on response protocol: {}'.format(self.reason)


def send_request(request, ip='', port=0, protocol=XML_PROTOCOL):
    """
    Sends a request to the designed KMIP server.

    Args:
        request (bytes): The message to be sent
        ip (str): IP of the HSM, if connecting remotely
        port (int): Port of the KMIP server within the HSM, if connecting remotely
        protocol (int): Messaging protocol; Anything other than TTLV implies HTTPS;
            TTLV is only HTTPS if port is different from 5696

    Returns:
        The response
    """
    if protocol not in _protocols:
        raise InvalidProtocolError(protocol)

    socket_path = os.getenv('KMIP_SERVER_SOCKET')

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(socket_path)
    try:
        sock.sendall(protocol)

        request_len_bytes = struct.pack("<I", len(request))
        sock.sendall(request_len_bytes)

        sock.sendall(request)
        sock.shutdown(socket.SHUT_WR)

        # Unpack the received length from little-endian to the native endianess
        response_len_bytes = recvall(sock, 4)
        response_len = struct.unpack("<I", response_len_bytes)[0]

        response = recvall(sock, response_len)
    finally:
        sock.shutdown(socket.SHUT_RDWR)
        sock.close()

    return response
