# coding=utf-8
from __future__ import (print_function, division, unicode_literals, absolute_import)

import datetime
import json
from xml.etree import ElementTree as ET

import iso8601
import pytest

from kkmip import enums
from kkmip import ttv
from kkmip.ttv import json as ttv_json
from kkmip.ttv import ttlv
from kkmip.ttv import xml


class TZ(datetime.tzinfo):
    def utcoffset(self, dt):
        return datetime.timedelta(minutes=-60)


def test_encode_json_integer():
    r = ttv_json.encode_integer(1)
    assert r == 1

    r = ttv_json.encode_integer(-1)
    assert r == -1


def test_decode_json_integer():
    r = ttv_json.decode_integer(enums.Tag.CryptographicUsageMask, '0x1')
    assert r == 1

    r = ttv_json.decode_integer(enums.Tag.CryptographicUsageMask, '-1')
    assert r == -1
    r = ttv_json.decode_integer(enums.Tag.CryptographicUsageMask, '0xffffffff')
    assert r == -1

    r = ttv_json.decode_integer(enums.Tag.CryptographicUsageMask, 'Encrypt|Decrypt|0x00000001')
    assert r == enums.CryptographicUsageMask.Encrypt | enums.CryptographicUsageMask.Decrypt | 1


def test_encode_json_longinteger():
    r = ttv_json.encode_longinteger(1)
    assert r == '0x0000000000000001'

    r = ttv_json.encode_longinteger(-1)
    assert r == '0xffffffffffffffff'


def test_decode_json_longinteger():
    r = ttv_json.decode_longinteger('1')
    assert r == 1
    r = ttv_json.decode_longinteger('0x1')
    assert r == 1

    r = ttv_json.decode_longinteger('-1')
    assert r == -1
    r = ttv_json.decode_longinteger('0xffffffff')
    assert r == 0xffffffff
    r = ttv_json.decode_longinteger('0xffffffffffffffff')
    assert r == -1


def test_encode_json_big_integer():
    r = ttv_json.encode_biginteger(1)
    assert r == '0x0000000000000001'

    r = ttv_json.encode_biginteger(1 << 62)
    assert r == '0x4000000000000000'

    r = ttv_json.encode_biginteger(1 << 63)
    assert r == '0x00000000000000008000000000000000'

    r = ttv_json.encode_biginteger(-1)
    assert r == '0xffffffffffffffff'


def test_decode_json_biginteger():
    r = ttv_json.decode_biginteger('0x0000000000000001')
    assert r == ttv.BigInteger(1)

    r = ttv_json.decode_biginteger('0x4000000000000000')
    assert r == ttv.BigInteger(1 << 62)

    r = ttv_json.decode_biginteger('0x00000000000000008000000000000000')
    assert r == ttv.BigInteger(1 << 63)

    r = ttv_json.decode_biginteger('0xffffffffffffffff')
    assert r == ttv.BigInteger(-1)


def test_encode_json_enumeration():
    r = ttv_json.encode_enumeration(enums.BlockCipherMode.CBC, enums.Tag.BlockCipherMode)
    assert r == 'CBC'

    r = ttv_json.encode_enumeration(enums.BlockCipherMode.CBC, enums.Tag.AttributeValue)
    assert r == 'CBC'


def test_decode_json_enumeration():
    r = ttv_json.decode_enumeration(enums.Tag.BlockCipherMode, 'CBC')
    assert r == enums.BlockCipherMode.CBC

    r = ttv_json.decode_enumeration(enums.Tag.BlockCipherMode, 1)
    assert r == enums.BlockCipherMode.CBC

    r = ttv_json.decode_enumeration(enums.Tag.BlockCipherMode, '0x00000001')
    assert r == enums.BlockCipherMode.CBC

    r = ttv_json.decode_enumeration(enums.Tag.BlockCipherMode, 1000)
    assert r == 1000


def test_encode_json_boolean():
    r = ttv_json.encode_boolean(True)
    assert r == True


def test_decode_json_boolean():
    r = ttv_json.decode_boolean(True)
    assert r == True

    r = ttv_json.decode_boolean('0x0000000000000001')
    assert r == True

    r = ttv_json.decode_boolean('0x0000000000000000')
    assert r == False


def test_encode_json_textstring():
    r = ttv_json.encode_textstring('çã')
    assert r == 'çã'


def test_decode_json_textstring():
    r = ttv_json.decode_textstring('çã')
    assert r == 'çã'


def test_encode_json_bytestring():
    r = ttv_json.encode_bytestring(b'\x01\xff')
    assert r == '01ff'


def test_decode_json_bytestring():
    r = ttv_json.decode_bytestring('01ff')
    assert r == b'\x01\xff'


def test_encode_json_datetime():
    r = ttv_json.encode_datetime(datetime.datetime(2001, 1, 1, 10, 0, 0, tzinfo=TZ()))
    assert r == '2001-01-01T10:00:00-01:00'

    r = ttv_json.encode_datetime(datetime.datetime(2001, 1, 1, 10, 0, 0, 10, tzinfo=TZ()))
    assert r == '2001-01-01T10:00:00-01:00'

    ttv_json.encode_datetime(datetime.datetime.now(iso8601.UTC))

    with pytest.raises(RuntimeError):
        ttv_json.encode_datetime(datetime.datetime.now())

    with pytest.raises(RuntimeError):
        ttv_json.encode_datetime(datetime.datetime.utcnow())


def test_decode_json_datetime():
    r = ttv_json.decode_datetime('2001-01-01T10:00:00-01:00')
    assert r == datetime.datetime(2001, 1, 1, 10, 0, 0, tzinfo=TZ())


def test_encode_json_interval():
    r = ttv_json.encode_interval(datetime.timedelta(days=1, seconds=1))
    assert r == 24 * 60 * 60 + 1


def test_decode_json_interval():
    r = ttv_json.decode_interval(24 * 60 * 60 + 1)
    assert r == datetime.timedelta(days=1, seconds=1)


def test_encode_json():
    tree = ttv.TTV(enums.Tag.ProtocolVersion, [
        ttv.TTV(enums.Tag.ProtocolVersionMajor, 1),
        ttv.TTV(enums.Tag.ProtocolVersionMinor, 2),
        ttv.TTV(enums.Tag.CryptographicLength, ttv.LongInteger(1 << 32)),
        ttv.TTV(enums.Tag.Modulus, ttv.BigInteger(1 << 64)),
        ttv.TTV(enums.Tag.NameValue, 'çã'),
        ttv.TTV(enums.Tag.IVCounterNonce, b'\x01\x02'),
        ttv.TTV(enums.Tag.OriginalCreationDate,
                datetime.datetime(2001, 1, 1, 10, 0, 0, tzinfo=TZ())),
        ttv.TTV(enums.Tag.LeaseTime, datetime.timedelta(days=1, seconds=1)),
        ttv.TTV(enums.Tag.BlockCipherMode, enums.BlockCipherMode.CBC),
    ])
    got = tree.encode_json()
    want = {'tag': 'ProtocolVersion', 'value': [
        {'tag': 'ProtocolVersionMajor', 'type': 'Integer', 'value': 1},
        {'tag': 'ProtocolVersionMinor', 'type': 'Integer', 'value': 2},
        {'tag': 'CryptographicLength', 'type': 'LongInteger', 'value': '0x0000000100000000'},
        {'tag': 'Modulus', 'type': 'BigInteger', 'value': '0x00000000000000010000000000000000'},
        {'tag': 'NameValue', 'type': 'TextString', 'value': 'çã'},
        {'tag': 'IVCounterNonce', 'type': 'ByteString', 'value': '0102'},
        {'tag': 'OriginalCreationDate', 'type': 'DateTime', 'value': '2001-01-01T10:00:00-01:00'},
        {'tag': 'LeaseTime', 'type': 'Interval', 'value': 24 * 60 * 60 + 1},
        {'tag': 'BlockCipherMode', 'type': 'Enumeration', 'value': 'CBC'},
    ]}
    assert got == want
    # Ensure it does not throw exceptions
    encoded = json.dumps(got)
    decoded = json.loads(encoded)
    assert decoded == got


def test_decode_json():
    tree = {'tag': 'ProtocolVersion', 'value': [
        {'tag': 'ProtocolVersionMajor', 'type': 'Integer', 'value': 1},
        {'tag': 'ProtocolVersionMinor', 'type': 'Integer', 'value': 2},
        {'tag': 'CryptographicLength', 'type': 'LongInteger', 'value': '0x0000000100000000'},
        {'tag': 'Modulus', 'type': 'BigInteger', 'value': '0x00000000000000010000000000000000'},
        {'tag': 'NameValue', 'type': 'TextString', 'value': 'çã'},
        {'tag': 'IVCounterNonce', 'type': 'ByteString', 'value': '0102'},
        {'tag': 'OriginalCreationDate', 'type': 'DateTime', 'value': '2001-01-01T10:00:00-01:00'},
        {'tag': 'LeaseTime', 'type': 'Interval', 'value': 24 * 60 * 60 + 1},
        {'tag': 'BlockCipherMode', 'type': 'Enumeration', 'value': 'CBC'},
    ]}
    got = ttv_json.decode(tree)
    want = ttv.TTV(enums.Tag.ProtocolVersion, [
        ttv.TTV(enums.Tag.ProtocolVersionMajor, 1),
        ttv.TTV(enums.Tag.ProtocolVersionMinor, 2),
        ttv.TTV(enums.Tag.CryptographicLength, ttv.LongInteger(1 << 32)),
        ttv.TTV(enums.Tag.Modulus, ttv.BigInteger(1 << 64)),
        ttv.TTV(enums.Tag.NameValue, 'çã'),
        ttv.TTV(enums.Tag.IVCounterNonce, b'\x01\x02'),
        ttv.TTV(enums.Tag.OriginalCreationDate,
                datetime.datetime(2001, 1, 1, 10, 0, 0, tzinfo=TZ())),
        ttv.TTV(enums.Tag.LeaseTime, datetime.timedelta(days=1, seconds=1)),
        ttv.TTV(enums.Tag.BlockCipherMode, enums.BlockCipherMode.CBC),
    ])
    assert got == want


def test_encode_xml_integer():
    r = xml.encode_integer(1)
    assert r == '1'

    r = xml.encode_integer(-1)
    assert r == '-1'


def test_decode_xml_integer():
    r = xml.decode_integer(enums.Tag.CryptographicUsageMask, '1')
    assert r == 1
    r = xml.decode_integer(enums.Tag.CryptographicUsageMask, '0x1')
    assert r == 1

    r = xml.decode_integer(enums.Tag.CryptographicUsageMask, '-1')
    assert r == -1
    r = xml.decode_integer(enums.Tag.CryptographicUsageMask, '0xffffffff')
    assert r == -1

    r = xml.decode_integer(enums.Tag.CryptographicUsageMask, 'Encrypt Decrypt 0x00000001')
    assert r == enums.CryptographicUsageMask.Encrypt | enums.CryptographicUsageMask.Decrypt | 1


def test_encode_xml_longinteger():
    r = xml.encode_longinteger(1)
    assert r == '1'

    r = xml.encode_longinteger(-1)
    assert r == '-1'


def test_decode_xml_longinteger():
    r = xml.decode_longinteger('1')
    assert r == 1
    r = xml.decode_longinteger('0x1')
    assert r == 1

    r = xml.decode_longinteger('-1')
    assert r == -1
    r = xml.decode_longinteger('0xffffffff')
    assert r == 0xffffffff
    r = xml.decode_longinteger('0xffffffffffffffff')
    assert r == -1


def test_encode_xml_big_integer():
    r = xml.encode_biginteger(1)
    assert r == '0000000000000001'

    r = xml.encode_biginteger(1 << 62)
    assert r == '4000000000000000'

    r = xml.encode_biginteger(1 << 63)
    assert r == '00000000000000008000000000000000'

    r = xml.encode_biginteger(-1)
    assert r == 'ffffffffffffffff'


def test_decode_xml_biginteger():
    r = xml.decode_biginteger('0000000000000001')
    assert r == ttv.BigInteger(1)

    r = xml.decode_biginteger('4000000000000000')
    assert r == ttv.BigInteger(1 << 62)

    r = xml.decode_biginteger('00000000000000008000000000000000')
    assert r == ttv.BigInteger(1 << 63)

    r = xml.decode_biginteger('ffffffffffffffff')
    assert r == ttv.BigInteger(-1)


def test_encode_xml_enumeration():
    r = xml.encode_enumeration(enums.BlockCipherMode.CBC, enums.Tag.BlockCipherMode)
    assert r == 'CBC'

    r = xml.encode_enumeration(enums.BlockCipherMode.CBC, enums.Tag.AttributeValue)
    assert r == 'CBC'

    r = xml.encode_enumeration(0x10000001, enums.Tag.BlockCipherMode)
    assert r == '0x10000001'


def test_decode_xml_enumeration():
    r = xml.decode_enumeration(enums.Tag.BlockCipherMode, '0x00000001')
    assert r == enums.BlockCipherMode.CBC

    r = xml.decode_enumeration(enums.Tag.BlockCipherMode, 'CBC')
    assert r == enums.BlockCipherMode.CBC

    r = xml.decode_enumeration(enums.Tag.BlockCipherMode, '0x10000001')
    assert r == 0x10000001


def test_encode_xml_boolean():
    r = xml.encode_boolean(True)
    assert r == 'true'
    r = xml.encode_boolean(False)
    assert r == 'false'


def test_decode_xml_boolean():
    r = xml.decode_boolean('true')
    assert r is True

    r = xml.decode_boolean('false')
    assert r is False


def test_encode_xml_textstring():
    r = xml.encode_textstring('çã')
    assert r == 'çã'


def test_decode_xml_textstring():
    r = xml.decode_textstring('çã')
    assert r == 'çã'


def test_encode_xml_bytestring():
    r = xml.encode_bytestring(b'\x01\xff')
    assert r == '01ff'


def test_decode_xml_bytestring():
    r = xml.decode_bytestring('01ff')
    assert r == b'\x01\xff'


def test_encode_xml_datetime():
    r = xml.encode_datetime(datetime.datetime(2001, 1, 1, 10, 0, 0, tzinfo=TZ()))
    assert r == '2001-01-01T10:00:00-01:00'

    r = xml.encode_datetime(datetime.datetime(2001, 1, 1, 10, 0, 0, 10, tzinfo=TZ()))
    assert r == '2001-01-01T10:00:00-01:00'

    xml.encode_datetime(datetime.datetime.now(iso8601.UTC))

    with pytest.raises(RuntimeError):
        xml.encode_datetime(datetime.datetime.now())

    with pytest.raises(RuntimeError):
        xml.encode_datetime(datetime.datetime.utcnow())


def test_decode_xml_datetime():
    r = xml.decode_datetime('2001-01-01T10:00:00-01:00')
    assert r == datetime.datetime(2001, 1, 1, 10, 0, 0, tzinfo=TZ())


def test_encode_xml_interval():
    r = xml.encode_interval(datetime.timedelta(days=1, seconds=1))
    assert r == str(24 * 60 * 60 + 1)


def test_decode_xml_interval():
    r = xml.decode_interval(str(24 * 60 * 60 + 1))
    assert r == datetime.timedelta(days=1, seconds=1)


def test_encode_xml():
    tree = ttv.TTV(enums.Tag.ProtocolVersion, [
        ttv.TTV(enums.Tag.ProtocolVersionMajor, 1),
        ttv.TTV(enums.Tag.ProtocolVersionMinor, 2),
        ttv.TTV(enums.Tag.CryptographicLength, ttv.LongInteger(1 << 32)),
        ttv.TTV(enums.Tag.Modulus, ttv.BigInteger(1 << 64)),
        ttv.TTV(enums.Tag.NameValue, 'çã'),
        ttv.TTV(enums.Tag.IVCounterNonce, b'\x01\x02'),
        ttv.TTV(enums.Tag.OriginalCreationDate,
                datetime.datetime(2001, 1, 1, 10, 0, 0, tzinfo=TZ())),
        ttv.TTV(enums.Tag.LeaseTime, datetime.timedelta(days=1, seconds=1)),
        ttv.TTV(enums.Tag.BlockCipherMode, enums.BlockCipherMode.CBC),
    ])
    got = tree.encode_xml()
    want = ET.Element('ProtocolVersion')
    want.extend([
        ET.Element('ProtocolVersionMajor', {'type': 'Integer', 'value': '1'}),
        ET.Element('ProtocolVersionMinor', {'type': 'Integer', 'value': '2'}),
        ET.Element('CryptographicLength', {'type': 'LongInteger', 'value': '4294967296'}),
        ET.Element('Modulus', {'type': 'BigInteger', 'value': '00000000000000010000000000000000'}),
        ET.Element('NameValue', {'type': 'TextString', 'value': 'çã'}),
        ET.Element('IVCounterNonce', {'type': 'ByteString', 'value': '0102'}),
        ET.Element('OriginalCreationDate',
                   {'type': 'DateTime', 'value': '2001-01-01T10:00:00-01:00'}),
        ET.Element('LeaseTime', {'type': 'Interval', 'value': '86401'}),
        ET.Element('BlockCipherMode', {'type': 'Enumeration', 'value': 'CBC'}),
    ])
    assert ET.tostring(got, encoding='utf-8') == ET.tostring(want, encoding='utf-8')


def test_decode_xml():
    tree = ET.Element('ProtocolVersion')
    tree.extend([
        ET.Element('ProtocolVersionMajor', {'type': 'Integer', 'value': '1'}),
        ET.Element('ProtocolVersionMinor', {'type': 'Integer', 'value': '2'}),
        ET.Element('CryptographicLength', {'type': 'LongInteger', 'value': '4294967296'}),
        ET.Element('Modulus', {'type': 'BigInteger', 'value': '00000000000000010000000000000000'}),
        ET.Element('NameValue', {'type': 'TextString', 'value': 'çã'}),
        ET.Element('IVCounterNonce', {'type': 'ByteString', 'value': '0102'}),
        ET.Element('OriginalCreationDate',
                   {'type': 'DateTime', 'value': '2001-01-01T10:00:00-01:00'}),
        ET.Element('LeaseTime', {'type': 'Interval', 'value': '86401'}),
        ET.Element('BlockCipherMode', {'type': 'Enumeration', 'value': 'CBC'}),
    ])
    got = ttv.decode_xml(tree)
    want = ttv.TTV(enums.Tag.ProtocolVersion, [
        ttv.TTV(enums.Tag.ProtocolVersionMajor, 1),
        ttv.TTV(enums.Tag.ProtocolVersionMinor, 2),
        ttv.TTV(enums.Tag.CryptographicLength, ttv.LongInteger(1 << 32)),
        ttv.TTV(enums.Tag.Modulus, ttv.BigInteger(1 << 64)),
        ttv.TTV(enums.Tag.NameValue, 'çã'),
        ttv.TTV(enums.Tag.IVCounterNonce, b'\x01\x02'),
        ttv.TTV(enums.Tag.OriginalCreationDate,
                datetime.datetime(2001, 1, 1, 10, 0, 0, tzinfo=TZ())),
        ttv.TTV(enums.Tag.LeaseTime, datetime.timedelta(days=1, seconds=1)),
        ttv.TTV(enums.Tag.BlockCipherMode, enums.BlockCipherMode.CBC),
    ])
    assert got == want


def test_encode_xml_string():
    root = ttv.TTV(enums.Tag.ProtocolVersionMajor, 1)
    got = xml.encode_to_string(root.encode_xml())
    want = b'<ProtocolVersionMajor type="Integer" value="1" />'
    assert got == want


def test_decode_xml_string():
    val = b'<ProtocolVersionMajor type="Integer" value="1" />'
    got = ttv.decode_xml(xml.decode_from_string(val))
    want = ttv.TTV(enums.Tag.ProtocolVersionMajor, 1)
    assert got == want


def test_encode_ttlv_integer():
    r = ttlv.encode_integer(1)
    assert r == b'\x00\x00\x00\x01'

    r = ttlv.encode_integer(-1)
    assert r == b'\xff\xff\xff\xff'


def test_decode_ttlv_integer():
    r = ttlv.decode_integer(b'\x00\x00\x00\x01')
    assert r == 1

    r = ttlv.decode_integer(b'\xff\xff\xff\xff')
    assert r == -1


def test_encode_ttlv_longinteger():
    r = ttlv.encode_longinteger(1)
    assert r == b'\x00\x00\x00\x00\x00\x00\x00\x01'

    r = ttlv.encode_longinteger(-1)
    assert r == b'\xff\xff\xff\xff\xff\xff\xff\xff'


def test_decode_ttlv_longinteger():
    r = ttlv.decode_longinteger(b'\x00\x00\x00\x00\x00\x00\x00\x01')
    assert r == 1

    r = ttlv.decode_longinteger(b'\xff\xff\xff\xff\xff\xff\xff\xff')
    assert r == -1


def test_encode_ttlv_biginteger():
    r = ttlv.encode_biginteger(1)
    assert r == b'\x00' * 7 + b'\x01'

    r = ttlv.encode_biginteger(1 << 62)
    assert r == b'\x40' + b'\x00' * 7

    r = ttlv.encode_biginteger(1 << 63)
    assert r == b'\x00' * 8 + b'\x80' + b'\x00' * 7

    r = ttlv.encode_biginteger(-1)
    assert r == b'\xFF' * 8


def test_decode_ttlv_biginteger():
    r = ttlv.decode_biginteger(b'\x00' * 7 + b'\x01')
    assert r == 1

    r = ttlv.decode_biginteger(b'\x40' + b'\x00' * 7)
    assert r == 1 << 62

    r = ttlv.decode_biginteger(b'\x00' * 8 + b'\x80' + b'\x00' * 7)
    assert r == 1 << 63

    r = ttlv.decode_biginteger(b'\xFF' * 8)
    assert r == -1


def test_encode_ttlv_enumeration():
    r = ttlv.encode_enumeration(enums.BlockCipherMode.CBC, enums.Tag.BlockCipherMode)
    assert r == b'\x00\x00\x00\x01'

    r = ttlv.encode_enumeration(enums.BlockCipherMode.CBC, enums.Tag.AttributeValue)
    assert r == b'\x00\x00\x00\x01'


def test_decode_ttlv_enumeration():
    r = ttlv.decode_enumeration(enums.Tag.BlockCipherMode, b'\x00\x00\x00\x01')
    assert r == enums.BlockCipherMode.CBC

    r = ttlv.decode_enumeration(enums.Tag.BlockCipherMode, b'\x00\x00\x01\x00')
    assert r == 256


def test_encode_ttlv_textstring():
    r = ttlv.encode_textstring('çã')
    assert r == 'çã'.encode('utf-8')


def test_decode_ttlv_textstring():
    r = ttlv.decode_textstring('çã'.encode('utf-8'))
    assert r == 'çã'


def test_encode_ttlv_bytestring():
    r = ttlv.encode_bytestring(b'\x01\xff')
    assert r == b'\x01\xff'


def test_decode_ttlv_bytestring():
    r = ttlv.decode_bytestring(b'\x01\xff')
    assert r == b'\x01\xff'


def test_encode_ttlv_datetime():
    r = ttlv.encode_datetime(datetime.datetime(2008, 3, 14, 11, 56, 40, tzinfo=iso8601.UTC))
    assert r == b'\x00\x00\x00\x00\x47\xDA\x67\xF8'

    ttlv.encode_datetime(datetime.datetime.now(iso8601.UTC))

    with pytest.raises(RuntimeError):
        ttlv.encode_datetime(datetime.datetime.now())

    with pytest.raises(RuntimeError):
        ttlv.encode_datetime(datetime.datetime.utcnow())


def test_decode_ttlv_datetime():
    r = ttlv.decode_datetime(b'\x00\x00\x00\x00\x47\xDA\x67\xF8')
    assert r == datetime.datetime(2008, 3, 14, 11, 56, 40, tzinfo=iso8601.UTC)


def test_encode_ttlv_interval():
    r = ttlv.encode_interval(datetime.timedelta(days=1, seconds=1))
    assert r == b'\x00\x01\x51\x81'


def test_decode_ttlv_interval():
    r = ttlv.decode_interval(b'\x00\x01\x51\x81')
    assert r == datetime.timedelta(days=1, seconds=1)


def test_encode_ttlv():
    tree = ttv.TTV(enums.Tag.ProtocolVersion, [
        ttv.TTV(enums.Tag.ProtocolVersionMajor, 1),
        ttv.TTV(enums.Tag.ProtocolVersionMinor, 2),
        ttv.TTV(enums.Tag.CryptographicLength, ttv.LongInteger(1 << 32)),
        ttv.TTV(enums.Tag.Modulus, ttv.BigInteger(1 << 64)),
        ttv.TTV(enums.Tag.NameValue, 'çã'),
        ttv.TTV(enums.Tag.IVCounterNonce, b'\x01\x02'),
        ttv.TTV(enums.Tag.OriginalCreationDate,
                datetime.datetime(2008, 3, 14, 11, 56, 40, tzinfo=iso8601.UTC)),
        ttv.TTV(enums.Tag.LeaseTime, datetime.timedelta(days=1, seconds=1)),
        ttv.TTV(enums.Tag.BlockCipherMode, enums.BlockCipherMode.CBC),
    ])
    got = tree.encode_ttlv()
    want = (b'\x42\x00\x69\x01' + b'\x00\x00\x00\x98'
            + (b'\x42\x00\x6A\x02' + b'\x00\x00\x00\x04' + b'\x00\x00\x00\x01\x00\x00\x00\x00')
            + (b'\x42\x00\x6B\x02' + b'\x00\x00\x00\x04' + b'\x00\x00\x00\x02\x00\x00\x00\x00')
            + (b'\x42\x00\x2A\x03' + b'\x00\x00\x00\x08' + b'\x00\x00\x00\x01\x00\x00\x00\x00')
            + (b'\x42\x00\x52\x04' + b'\x00\x00\x00\x10' + b'\x00\x00\x00\x00\x00\x00\x00\x01'
               + b'\x00\x00\x00\x00\x00\x00\x00\x00')
            + (b'\x42\x00\x55\x07' + b'\x00\x00\x00\x04' + b'\xc3\xa7\xc3\xa3\x00\x00\x00\x00')
            + (b'\x42\x00\x3D\x08' + b'\x00\x00\x00\x02' + b'\x01\x02\x00\x00\x00\x00\x00\x00')
            + (b'\x42\x00\xBC\x09' + b'\x00\x00\x00\x08' + b'\x00\x00\x00\x00\x47\xDA\x67\xF8')
            + (b'\x42\x00\x49\x0A' + b'\x00\x00\x00\x04' + b'\x00\x01\x51\x81\x00\x00\x00\x00')
            + (b'\x42\x00\x11\x05' + b'\x00\x00\x00\x04' + b'\x00\x00\x00\x01\x00\x00\x00\x00')
            )

    assert got == want


def test_decode_ttlv():
    tree = (b'\x42\x00\x69\x01' + b'\x00\x00\x00\x98'
            + (b'\x42\x00\x6A\x02' + b'\x00\x00\x00\x04' + b'\x00\x00\x00\x01\x00\x00\x00\x00')
            + (b'\x42\x00\x6B\x02' + b'\x00\x00\x00\x04' + b'\x00\x00\x00\x02\x00\x00\x00\x00')
            + (b'\x42\x00\x2A\x03' + b'\x00\x00\x00\x08' + b'\x00\x00\x00\x01\x00\x00\x00\x00')
            + (b'\x42\x00\x52\x04' + b'\x00\x00\x00\x10' + b'\x00\x00\x00\x00\x00\x00\x00\x01'
               + b'\x00\x00\x00\x00\x00\x00\x00\x00')
            + (b'\x42\x00\x55\x07' + b'\x00\x00\x00\x04' + b'\xc3\xa7\xc3\xa3\x00\x00\x00\x00')
            + (b'\x42\x00\x3D\x08' + b'\x00\x00\x00\x02' + b'\x01\x02\x00\x00\x00\x00\x00\x00')
            + (b'\x42\x00\xBC\x09' + b'\x00\x00\x00\x08' + b'\x00\x00\x00\x00\x47\xDA\x67\xF8')
            + (b'\x42\x00\x49\x0A' + b'\x00\x00\x00\x04' + b'\x00\x01\x51\x81\x00\x00\x00\x00')
            + (b'\x42\x00\x11\x05' + b'\x00\x00\x00\x04' + b'\x00\x00\x00\x01\x00\x00\x00\x00')
            )
    got = ttlv.decode(tree)
    want = ttv.TTV(enums.Tag.ProtocolVersion, [
        ttv.TTV(enums.Tag.ProtocolVersionMajor, 1),
        ttv.TTV(enums.Tag.ProtocolVersionMinor, 2),
        ttv.TTV(enums.Tag.CryptographicLength, ttv.LongInteger(1 << 32)),
        ttv.TTV(enums.Tag.Modulus, ttv.BigInteger(1 << 64)),
        ttv.TTV(enums.Tag.NameValue, 'çã'),
        ttv.TTV(enums.Tag.IVCounterNonce, b'\x01\x02'),
        ttv.TTV(enums.Tag.OriginalCreationDate,
                datetime.datetime(2008, 3, 14, 11, 56, 40, tzinfo=iso8601.UTC)),
        ttv.TTV(enums.Tag.LeaseTime, datetime.timedelta(days=1, seconds=1)),
        ttv.TTV(enums.Tag.BlockCipherMode, enums.BlockCipherMode.CBC),
    ])
    assert got == want


def test_ttv_with_type():
    node = ttv.TTV(enums.Tag.ProtocolVersionMajor, '1', enums.ItemType.Integer)
    assert node.value == 1
    node = ttv.TTV(enums.Tag.ProtocolVersionMajor, 1, enums.ItemType.Integer)
    assert node.value == 1
    ttv.TTV(enums.Tag.ActivationDate, datetime.datetime.utcnow(), enums.ItemType.DateTime)
