"""
TTV -> XML encoding / decoding.

These functions work with ElementTree.Element trees which are ready to be serialized as strings
(and not with the serialized XML strings themselves).
"""
from __future__ import (print_function, division, unicode_literals, absolute_import)

import codecs
import datetime
from xml.etree import ElementTree as ET

import iso8601
from eight import int, str, PY2, builtins

from kkmip import enums
from kkmip.ttv import common
from kkmip.ttv import types

if PY2:
    _integer_types = (builtins.int, builtins.long,)
    # etree tries to be too smart and converts values to 'str' when possible (e.g. ascii).
    # This monkey-patch forces it to always use 'unicode'
    ET.XMLTreeBuilder._fixtext = lambda self, text: text
else:
    _integer_types = (builtins.int,)


def encode_to_string(root):
    """
    Encode an Element tree into a XML UTF-8 byte string.

    Args:
        root (ElementTree.Element): the root of the Element tree

    Returns:
        bytes: the XML encoded with UTF-8.
    """
    return ET.tostring(root, encoding='utf-8')


def decode_from_string(xml):
    """
    Decode a XML UTF-8 byte string into an Element tree.

    Args:
        xml (bytes): the UTF-8 encoded XML byte string.

    Returns:
        ElementTree.Element: the root of the Element tree.
    """
    return ET.fromstring(xml.decode('utf-8'))


def encode(root):
    """
    Encode a TTV tree into an Element tree.

    Args:
        root (ttv.TTV): the TTV root

    Returns:
        ElementTree.Element: encoded root
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

    e = ET.Element(root.tag.name)
    if root.typ == enums.ItemType.Structure:
        e.extend(value)
    else:
        e.set('type', root.typ.name)
        e.set('value', value)
    return e


def decode(root):
    """
    Decode an Element tree into a TTV tree.

    Args:
        root (ElementTree.Element): the root of the Element tree.

    Returns:
        TTV: the root of the decoded TTV tree.
    """
    if root.tag == 'TTLV':
        tag = root.get('tag', None)
        if tag is None:
            raise RuntimeError('Missing tag key')
        tag = int(tag, 16)
    else:
        tag = root.tag
        tag = enums.Tag[tag]

    typ = root.get('type', 'Structure')
    typ = enums.ItemType[typ]

    if typ == enums.ItemType.Structure:
        value = list(root)
    else:
        value = root.get('value', None)
    if value is None:
        raise RuntimeError('Missing value key')

    root = {
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
    if typ in (enums.ItemType.Enumeration, enums.ItemType.Integer):
        decoded_value = root[typ](tag, value)
    else:
        decoded_value = root[typ](value)

    from kkmip import ttv
    return ttv.TTV(tag, decoded_value, typ)


def encode_structure(val):
    """
    Encode a Structure in a list of XML elements.

    Args:
        val (list of TTV): the input.

    Returns:
        list of .ElementTree.Element: the encoded result.
    """
    return [elem.encode_xml() for elem in val]


def decode_structure(val):
    """
    Decode a Structure from a list of XML elements.

    Args:
        val (list of .ElementTree.Element): the input.

    Returns:
        list of TTV: the result.
    """
    return [decode(elem) for elem in val]


def encode_integer(val):
    """
    Encode a Integer into a XML-suitable string.

    Args:
        val (ttv.Integer): the input.

    Returns:
        str: the result.
    """
    return str(val)


def decode_integer(tag, val):
    """
    Decode a Integer from a XML-suitable string.

    Args:
        val (int or str): the input as an int, hex string (e.g. "0x00000001"), or enum string
            (for masks, e.g. "Sign")

    Returns:
        ttv.Integer or ttv.UnknownIntegerMask: the result.
    """
    try:
        return types.Integer(val)
    except ValueError:
        if val.startswith('0x'):
            return types.Integer(common.decode_int_str(val, 32))
        else:
            try:
                val = common.decode_integer_mask(tag, val.split(' '))
            # TODO: create a more specific exception
            except RuntimeError:
                return types.UnknownIntegerMask(val.split(' '))
            return types.Integer(val)


def encode_longinteger(val):
    """
    Encode a LongInteger into a XML-suitable string.

    Args:
        val (ttv.LongInteger): the input.

    Returns:
        str: the result.
    """
    return str(val)


def decode_longinteger(val):
    """
    Decode a LongInteger from a XML-suitable string.

    Args:
        val (str or int): the input as an int or hex string (e.g. "0x00000001")

    Returns:
        ttv.LongInteger: the result.
    """
    if val.startswith('0x'):
        return types.LongInteger(common.decode_int_str(val, 64))
    return types.LongInteger(val)


def encode_biginteger(val):
    """
    Encode a BigInteger into a XML-suitable string.

    Args:
        val (ttv.BigInteger): the input.

    Returns:
        str: the result.
    """
    return common.encode_int_str(val, 64)


def decode_biginteger(val):
    """
    Decode a BigInteger from a XML-suitable string.

    Args:
        val (str): the input as a xsd:hexBinary string (e.g. "0000000000000001")

    Returns:
        ttv.Integer: the result.
    """
    return types.BigInteger(common.decode_int_str(val, 64))


def encode_enumeration(val, tag):
    """
    Encode a Enumeration into a XML-suitable string.

    Args:
        val (Enum or UnknownEnumeration): the input.

    Returns:
        str: the result.
    """
    if isinstance(val, enums.Enum):
        return val.name
    return '0x{:0{}x}'.format(val, 32 // 4)


def decode_enumeration(tag, val):
    """
    Decode a Enumeration from a XML-suitable string.

    Args:
        tag (enums.Tag): the tag of the value; used to find the corresponding enumeration.
        val (str): the input as hex string (e.g. "0x00000001") or enum string
            (e.g. "CBC").

    Returns:
        Enum or UnknownEnumeration: the result; an UnknownEnumeration if the corresponding
            enumeration is not found.
    """
    try:
        if val.startswith('0x'):
            val = int(val, 16)
        enum_cls = getattr(enums, tag.name)
        if isinstance(val, _integer_types):
            return enum_cls(val)
        else:
            return enum_cls[val]
    except (AttributeError, ValueError):
        if isinstance(val, _integer_types):
            return types.UnknownEnumeration(val)
        return types.UnknownEnumerationString(val)


def encode_boolean(val):
    """
    Encode a Boolean into a XML-suitable string.

    Args:
        val (bool): the input.

    Returns:
        str: the result.
    """
    return 'true' if val else 'false'


def decode_boolean(val):
    """
    Decode a Boolean from a XML-suitable string.

    Args:
        val (str): the input as a string (e.g. "true")

    Returns:
        bool: the result.
    """
    return val == 'true'


def encode_textstring(val):
    """
    Encode a TextString into a XML-suitable string.

    Args:
        val (str): the input.

    Returns:
        str: the result.
    """
    return val


def decode_textstring(val):
    """
    Decode a TextString from a XML-suitable string.

    Args:
        val (str): the input

    Returns:
        str: the result.
    """
    return val


def encode_bytestring(val):
    """
    Encode a ByteString into a XML-suitable string.

    Args:
        val (bytes): the input.

    Returns:
        str: the result.
    """
    return codecs.encode(val, 'hex').decode('ascii')


def decode_bytestring(val):
    """
    Decode a ByteString from a XML-suitable string.

    Args:
        val (str): the input as a hex bytestring (e.g. "00000001")

    Returns:
        bytes: the result.
    """
    return codecs.decode(val.encode('ascii'), 'hex')


def encode_datetime(val):
    """
    Encode a DateTime into a XML-suitable string.

    Args:
        val (datetime.datetime): the input.

    Returns:
        str: the result.
    """
    if val.tzinfo is None:
        raise RuntimeError(
            'Datetime object must have timezone information (tzinfo): {}'.format(val))
    val = val.replace(microsecond=0)
    return val.isoformat()


def decode_datetime(val):
    """
    Decode a DateTime from a XML-suitable string.

    Args:
        val (str or int): the input as an int or ISO8601 string.

    Returns:
        datetime.datetime: the result.
    """
    if val.startswith('0x'):
        return datetime.datetime.fromtimestamp(int(val, 16), iso8601.UTC)
    return iso8601.parse_date(val)


def encode_interval(val):
    """
    Encode a Interval into a XML-suitable string.

    Args:
        val (datetime.timedelta): the input.

    Returns:
        str: the result.
    """
    return str(int(val.total_seconds()))


def decode_interval(val):
    """
    Decode a Integer from a XML-suitable string.

    Args:
        val (str): the input as a string

    Returns:
        datetime.timedelta: the result.
    """
    return datetime.timedelta(seconds=int(val))
