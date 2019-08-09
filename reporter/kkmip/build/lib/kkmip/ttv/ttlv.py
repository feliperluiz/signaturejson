"""
TTV -> TTLV encoding / decoding.
"""
from __future__ import (print_function, division, unicode_literals, absolute_import)

import calendar
import datetime
import struct

import iso8601
from eight import int, PY2, builtins, range

from kkmip import enums
from kkmip.ttv import types

if PY2:
    _integer_types = (builtins.int, builtins.long,)
else:
    _integer_types = (builtins.int,)


def _to_bytes(n, length, endianess='big'):
    """
    Convert an int into a byte string.

    Used in Python 2 for the implementation of int.to_bytes from Python 3.
    """
    if PY2:
        h = b'%x' % n
        s = (b'0' * (len(h) % 2) + h).zfill(length * 2).decode('hex')
        return s if endianess == 'big' else s[::-1]
    else:
        return n.to_bytes(length, endianess)


def encode(root):
    """
    Encode a TTV tree into a TTLV byte string.

    Args:
        root (ttv.TTV): the value

    Returns:
        bytes: the encoded value.
    """
    d = {
        enums.ItemType.Structure: encode_structure,
        enums.ItemType.Integer: encode_integer,
        enums.ItemType.LongInteger: encode_longinteger,
        enums.ItemType.BigInteger: encode_biginteger,
        enums.ItemType.Enumeration: encode_enumeration,
        enums.ItemType.Boolean: encode_boolean,
        enums.ItemType.TextString: encode_textstring,
        enums.ItemType.ByteString: encode_bytestring,
        enums.ItemType.DateTime: encode_datetime,
        enums.ItemType.Interval: encode_interval,
    }
    if root.typ == enums.ItemType.Enumeration:
        value = d[root.typ](root.value, root.tag)
    else:
        value = d[root.typ](root.value)

    tt = struct.pack('>I', root.tag.value << 8 | root.typ.value)
    length = struct.pack('>I', len(value))
    ttlv = tt + length + value
    if len(value) % 8 != 0:
        pad_len = 8 - len(value) % 8
        pad = b'\x00' * pad_len
        ttlv += pad
    return ttlv


def decode(ttlv):
    """
    Decode a TTLV byte string in to a TTV tree.

    Args:
        ttlv (bytes): the input as a TTLV byte string.

    Returns:
        TTV: the TTV tree.
    """
    r, l = _decode(ttlv)
    if l != len(ttlv):
        raise RuntimeError('Input TTLV has unparsed trailing data')
    return r


def decode_header(ttlv):
    """
    Decode a TTLV 8-byte header.

    Args:
        ttlv (bytes): the 8-byte TTLV byte string header.

    Returns:
        tuple(int, int, int, int, int): the tag value, type value, header length, value length,
            padded value length.
    """
    offset = 0
    tt = struct.unpack_from('>I', ttlv, offset)[0]
    offset += struct.calcsize('>I')
    length = struct.unpack_from('>I', ttlv, offset)[0]
    offset += struct.calcsize('>I')

    padded_length = length
    if length % 8 != 0:
        padded_length = length + (8 - (length % 8))

    tag_value = tt >> 8
    typ_value = tt & 0xFF
    return tag_value, typ_value, offset, length, padded_length


def _decode(ttlv):
    """
    Decode a TTLV byte string into a TTV tree.

    Args:
        ttlv (bytes): the input as a TTLV byte string.

    Returns:
        tuple(TTV, length): the TTV tree and the length of the TTLV bytes consumed.
    """
    tag_value, typ_value, offset, length, padded_length = decode_header(ttlv)
    value = ttlv[offset:offset + length]

    tag = enums.Tag(tag_value)
    typ = enums.ItemType(typ_value)

    ttlv = {
        enums.ItemType.Structure: decode_structure,
        enums.ItemType.Integer: decode_integer,
        enums.ItemType.LongInteger: decode_longinteger,
        enums.ItemType.BigInteger: decode_biginteger,
        enums.ItemType.Enumeration: decode_enumeration,
        enums.ItemType.Boolean: decode_boolean,
        enums.ItemType.TextString: decode_textstring,
        enums.ItemType.ByteString: decode_bytestring,
        enums.ItemType.DateTime: decode_datetime,
        enums.ItemType.Interval: decode_interval,
    }
    if typ == enums.ItemType.Enumeration:
        decoded_value = ttlv[typ](tag, value)
    else:
        decoded_value = ttlv[typ](value)
    from kkmip.ttv import ttv
    return ttv.TTV(tag, decoded_value, typ), offset + padded_length


def encode_structure(val):
    """
    Encode a Structure into a TTLV byte string.

    Args:
        val (list of TTV): the input.

    Returns:
        bytes: the encoded result.
    """
    return b''.join(elem.encode_ttlv() for elem in val)


def decode_structure(val):
    """
    Decode a TTLV byte string into a Structure.

    Args:
        val (bytes): the input.

    Returns:
        list of TTV: the result.
    """
    r = []
    offset = 0
    while offset < len(val):
        node, length = _decode(val[offset:])
        r.append(node)
        offset += length
    return r


def encode_integer(val):
    """
    Encode an Integer into a TTV byte string.

    Args:
        val (ttv.Integer): the input.

    Returns:
        bytes: the result.
    """
    return struct.pack('>i', val)


def decode_integer(val):
    """
    Decode a TTLV byte string into an Integer.

    Args:
        val (bytes): the input

    Returns:
        ttv.Integer: the result.
    """
    return types.Integer(struct.unpack('>i', val)[0])


def encode_longinteger(val):
    """
    Encode a LongInteger into a TTV byte string.

    Args:
        val (ttv.LongInteger): the input.

    Returns:
        bytes: the result.
    """
    return struct.pack('>q', val)


def decode_longinteger(val):
    """
    Decode a TTV byte string into a LongInteger.

    Args:
        val (bytes): the input

    Returns:
        ttv.LongInteger: the result.
    """
    return types.LongInteger(struct.unpack('>q', val)[0])


def encode_biginteger(val):
    """
    Encode a BigInteger into a TTLV byte array.

    Args:
        val (ttv.BigInteger): the input.

    Returns:
        bytes: the result.
    """
    bit_len = val.bit_length()
    # round up to the next multiple of 64 bits, considering 1 additional sign bit
    bit_len = (((bit_len + 1) + 63) // 64) * 64
    if val < 0:
        # compute two's complemenent of val (2^bitLen - val) with 64-bit multiple size
        x = 1 << bit_len
        # val is already negative, just add it
        val += x
    return _to_bytes(val, bit_len // 8)


def decode_biginteger(val):
    """
    Decode a TTLV byte array into a big Integer.

    Args:
        val (bytes): the input

    Returns:
        ttv.Integer: the result.
    """
    group_size = struct.calcsize('>Q')
    bit_len = len(val) * 8
    # Unpach each group of 8 bytes, right-to-left, shift each group to its numeric position,
    # then add everything
    x = sum(struct.unpack('>Q', val[pos - group_size:pos])[0] << (i * 64)
            for i, pos in enumerate(range(len(val), 0, -group_size)))
    # If the upper bit is set, it is a negative number.
    if (x >> (bit_len - 1)) & 1:
        x -= 1 << bit_len
    return types.BigInteger(x)


def encode_enumeration(val, tag):
    """
    Encode a Enumeration into a TTLV byte string.

    Args:
        val (Enum or UnknownEnumeration): the input.

    Returns:
        bytes: the result.
    """
    if isinstance(val, enums.Enum):
        x = val.value
    else:
        x = val
    return struct.pack('>I', x)


def decode_enumeration(tag, val):
    """
    Decode a TTLV byte string into an Enumeration.

    Args:
        tag (enums.Tag): the tag of the value; used to find the corresponding enumeration.
        val (bytes): the input.

    Returns:
        Enum or UnknownEnumeration: the result; an UnknownEnumeration if the corresponding
            enumeration is not found.
    """
    try:
        val = struct.unpack('>I', val)[0]
        enum_cls = getattr(enums, tag.name)
        return enum_cls(val)
    except (AttributeError, ValueError):
        return types.UnknownEnumeration(val)


def encode_boolean(val):
    """
    Encode a Boolean into a TTLV byte string.

    Args:
        val (bool): the input.

    Returns:
        bytes: the result.
    """
    return b'\x00' * 7 + (b'\x01' if val else b'\x00')


def decode_boolean(val):
    """
    Decode a TTLV byte string into a Boolean.

    Args:
        val (bytes): the input

    Returns:
        bool: the result.
    """
    return val != b'\x00' * 8


def encode_textstring(val):
    """
    Encode a TextString into a TTLV byte string.

    Args:
        val (str): the input.

    Returns:
        bytes: the result.
    """
    return val.encode('utf-8')


def decode_textstring(val):
    """
    Decode a TTLV byte string into a TextString.

    Args:
        val (bytes): the input

    Returns:
        str: the result.
    """
    return val.decode('utf-8')


def encode_bytestring(val):
    """
    Encode a ByteString into a TTLV byte string.

    Args:
        val (bytes): the input.

    Returns:
        bytes: the result.
    """
    return val


def decode_bytestring(val):
    """
    Decode a TTLV byte string into a ByteString.

    Args:
        val (bytes): the input

    Returns:
        bytes: the result.
    """
    return val


def encode_datetime(val):
    """
    Encode a DateTime into a TTLV byte string.

    Args:
        val (datetime.datetime): the input.

    Returns:
        bytes: the result.
    """
    if val.tzinfo is None:
        raise RuntimeError(
            'Datetime object must have timezone information (tzinfo): {}'.format(val))
    x = calendar.timegm(val.replace(microsecond=0).utctimetuple())
    return encode_longinteger(x)


def decode_datetime(val):
    """
    Decode a TTLV byte string into a DateTime.

    Args:
        val (bytes): the input.

    Returns:
        datetime.datetime: the result.
    """
    x = decode_longinteger(val)
    return datetime.datetime.fromtimestamp(x, iso8601.UTC)


def encode_interval(val):
    """
    Encode a Interval into a TTLV byte string.

    Args:
        val (datetime.timedelta): the input.

    Returns:
        bytes: the result.
    """
    return struct.pack('>I', int(val.total_seconds()))


def decode_interval(val):
    """
    Decode a TTLV byte string into a Interval.

    Args:
        val (bytes): the input.

    Returns:
        datetime.timedelta: the result.
    """
    x = struct.unpack('>I', val)[0]
    return datetime.timedelta(seconds=x)
