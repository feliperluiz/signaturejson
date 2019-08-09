"""
TTV -> JSON encoding / decoding.

These functions work with Python dicts which are "JSON-compatible", i.e.,
are ready to be serialized as string with json.dumps (and not with the serialized JSON strings
themselves).
"""
from __future__ import (print_function, division, unicode_literals, absolute_import)

import codecs
import datetime
from collections import OrderedDict

import iso8601
from eight import int, str, PY2, builtins

from kkmip import enums
from kkmip.ttv import common
from kkmip.ttv import types

if PY2:
    _integer_types = (builtins.int, builtins.long,)
else:
    _integer_types = (builtins.int,)


def encode(root):
    """
    Encode a TTV tree into a JSON-encodable dicitionary tree.

    Args:
        root (ttv.TTV): the value

    Returns:
        dict: the encoded value.
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

    d = OrderedDict([('tag', root.tag.name)])
    if root.typ != enums.ItemType.Structure:
        d['type'] = root.typ.name
    d['value'] = value
    return d


def decode(d):
    """
    Decode a TTV tree from a JSON-encodable dictionary tree.

    Args:
        d (dict): the input as a KMIP JSON-encodable dictionary (with 'tag', 'type', 'value' keys)

    Returns:
        TTV: the TTV tree.
    """
    tag = d.get('tag', None)
    typ = d.get('type', 'Structure')
    value = d.get('value', None)
    if tag is None:
        raise RuntimeError('Missing tag key')
    if value is None:
        raise RuntimeError('Missing value key')
    tag = enums.Tag[tag]
    typ = enums.ItemType[typ]

    d = {
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
        decoded_value = d[typ](tag, value)
    else:
        decoded_value = d[typ](value)
    from kkmip.ttv import ttv
    return ttv.TTV(tag, decoded_value, typ)


def encode_structure(val):
    """
    Encode a Structure in a JSON-encodable list.

    Args:
        val (list of TTV): the input.

    Returns:
        list of JSON-encodable values: the encoded result.
    """
    return [elem.encode_json() for elem in val]


def decode_structure(val):
    """
    Decode a Structure from a JSON-encodable list.

    Args:
        val (list of JSON-encodable values): the input.

    Returns:
        list of TTV: the result.
    """
    return [decode(elem) for elem in val]


def encode_integer(val):
    """
    Encode a Integer into a JSON-encodable value.

    Args:
        val (ttv.Integer): the input.

    Returns:
        JSON-encodable value: the result.
    """
    return val


def decode_integer(tag, val):
    """
    Decode a Integer from a JSON-encodable value.

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
                val = common.decode_integer_mask(tag, val.split('|'))
            # TODO: create a more specific exception
            except RuntimeError:
                return types.UnknownIntegerMask(val.split('|'))
            return types.Integer(val)


def encode_longinteger(val):
    """
    Encode a LongInteger into a JSON-encodable value.

    Args:
        val (ttv.LongInteger): the input.

    Returns:
        JSON-encodable value: the result.
    """
    # Spec: Note that JS Numbers are 64-bit floating point and can only represent 53-bits of
    # precision, so any values >= 2^52 must be represented as hex strings.
    if val < 0:
        val += (1 << 64)
    return '0x{:016x}'.format(val)


def decode_longinteger(val):
    """
    Decode a LongInteger from a JSON-encodable value.

    Args:
        val (str or int): the input as an int or hex string (e.g. "0x00000001")

    Returns:
        ttv.LongInteger: the result.
    """
    if isinstance(val, str):
        return types.LongInteger(common.decode_int_str(val, 64))
    return types.LongInteger(val)


def encode_biginteger(val):
    """
    Encode a BigInteger into a JSON-encodable value.

    Args:
        val (ttv.BigInteger): the input.

    Returns:
        JSON-encodable value: the result.
    """
    return '0x' + common.encode_int_str(val, 64)


def decode_biginteger(val):
    """
    Decode a Integer from a JSON-encodable value.

    Args:
        val (str or int): the input as an int or hex string (e.g. "0x00000001")

    Returns:
        ttv.Integer: the result.
    """
    if isinstance(val, str):
        val = common.decode_int_str(val, 64)
    return types.BigInteger(val)


def encode_enumeration(val, tag):
    """
    Encode a Enumeration into a JSON-encodable value.

    Args:
        val (Enum or UnknownEnumeration): the input.

    Returns:
        JSON-encodable value: the result.
    """
    if isinstance(val, enums.Enum):
        return val.name
    return val


def decode_enumeration(tag, val):
    """
    Decode a Enumeration from a JSON-encodable value.

    Args:
        tag (enums.Tag): the tag of the value; used to find the corresponding enumeration.
        val (str or int): the input as an int, hex string (e.g. "0x00000001") or enum string
            (e.g. "CBC").

    Returns:
        Enum or UnknownEnumeration: the result; an UnknownEnumeration if the corresponding
            enumeration is not found.
    """
    try:
        if not isinstance(val, _integer_types) and val.startswith('0x'):
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
    Encode a Boolean into a JSON-encodable value.

    Args:
        val (bool): the input.

    Returns:
        JSON-encodable value: the result.
    """
    return val


def decode_boolean(val):
    """
    Decode a Boolean from a JSON-encodable value.

    Args:
        val (bool or str): the input as a bool or hex string (e.g. "0x00000001")

    Returns:
        bool: the result.
    """
    if not isinstance(val, bool):
        return bool(int(val, 16))
    return val


def encode_textstring(val):
    """
    Encode a TextString into a JSON-encodable value.

    Args:
        val (str): the input.

    Returns:
        JSON-encodable value: the result.
    """
    return val


def decode_textstring(val):
    """
    Decode a TextString from a JSON-encodable value.

    Args:
        val (str): the input

    Returns:
        str: the result.
    """
    return val


def encode_bytestring(val):
    """
    Encode a ByteString into a JSON-encodable value.

    Args:
        val (bytes): the input.

    Returns:
        JSON-encodable value: the result.
    """
    return codecs.encode(val, 'hex').decode('ascii')


def decode_bytestring(val):
    """
    Decode a ByteString from a JSON-encodable value.

    Args:
        val (str): the input as a hex bytestring (e.g. "00000001")

    Returns:
        bytes: the result.
    """
    return codecs.decode(val.encode('ascii'), 'hex')


def encode_datetime(val):
    """
    Encode a DateTime into a JSON-encodable value.

    Args:
        val (datetime.datetime): the input.

    Returns:
        JSON-encodable value: the result.
    """
    if val.tzinfo is None:
        raise RuntimeError(
            'Datetime object must have timezone information (tzinfo): {}'.format(val))
    val = val.replace(microsecond=0)
    return val.isoformat()


def decode_datetime(val):
    """
    Decode a DateTime from a JSON-encodable value.

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
    Encode a Interval into a JSON-encodable value.

    Args:
        val (datetime.timedelta): the input.

    Returns:
        JSON-encodable value: the result.
    """
    return val.total_seconds()


def decode_interval(val):
    """
    Decode a Integer from a JSON-encodable value.

    Args:
        val (str or int): the input as an int or hex string (e.g. "0x00000001")

    Returns:
        datetime.timedelta: the result.
    """
    if not isinstance(val, _integer_types):
        val = int(val, 16)
    return datetime.timedelta(seconds=val)
