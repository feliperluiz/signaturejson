"""
Main module for TTV code.
"""
from __future__ import (print_function, division, unicode_literals, absolute_import)

import datetime
import struct

from eight import bytes, str, PY2, builtins

from kkmip import enums
from kkmip.ttv import json
from kkmip.ttv import ttlv
from kkmip.ttv import types
from kkmip.ttv import xml

if PY2:
    _integer_types = (builtins.int, builtins.long,)
else:
    _integer_types = (builtins.int,)

_enums_types = (enums.Enum, types.UnknownEnumeration, types.UnknownEnumerationString)


def _enum_value(x):
    """ Convert a int/Enum value into a int"""
    if isinstance(x, _integer_types):
        return x
    return x.value


class TTV(object):
    """
    TTV represents a KMIP tag, type, value node.

    If the type is a KMIP Structure, then value is a list of TTV nodes, making it a tree.

    Args:
        tag (kkmip.enums.Tag): the KMIP tag of the node.
        value: the value of the node.
            Its Python type depend on typ:
            Integer: Integer
            LongInteger: LongInteger
            BigInterger: BigInterger
            Enumeration: Enum or Enumeration
            Boolean: bool
            TextString: str
            ByteString: bytes
            DateTime: datetime.datetime
            Interval: datetime.timedelta
        typ (kkmip.enums.ItemType): the KMIP type of the node. If None, it is automatically
            determined from the Python type of the value.
    """

    def __init__(self, tag, value, typ=None):
        self.tag = tag
        self.value = value
        if typ is None:
            if isinstance(value, types.LongInteger):
                self.typ = enums.ItemType.LongInteger
            elif isinstance(value, types.BigInteger):
                self.typ = enums.ItemType.BigInteger
            elif isinstance(value, _enums_types):
                self.typ = enums.ItemType.Enumeration
            elif isinstance(value, bool):
                self.typ = enums.ItemType.Boolean
            elif isinstance(value, str):
                self.typ = enums.ItemType.TextString
            elif isinstance(value, (bytes, bytearray)):
                self.typ = enums.ItemType.ByteString
            elif isinstance(value, datetime.datetime):
                self.typ = enums.ItemType.DateTime
            elif isinstance(value, datetime.timedelta):
                self.typ = enums.ItemType.Interval
            elif isinstance(value, list):
                self.typ = enums.ItemType.Structure
            elif isinstance(value, (types.Integer,) + _integer_types):
                self.typ = enums.ItemType.Integer
                self.value = types.Integer(self.value)
            else:
                raise RuntimeError(
                    'Value {} does not correspond to a TTLV type'.format(repr(value)))
        else:
            self.typ = typ
            if self.typ == enums.ItemType.Integer:
                if not isinstance(self.value, (types.Integer, types.UnknownIntegerMask)):
                    self.value = types.Integer(self.value)
            elif self.typ == enums.ItemType.LongInteger:
                self.value = types.LongInteger(self.value)
            elif self.typ == enums.ItemType.BigInteger:
                self.value = types.BigInteger(self.value)
            elif self.typ == enums.ItemType.Enumeration:
                if isinstance(self.value, _integer_types):
                    self.value = types.UnknownEnumeration(self.value)
            elif self.typ == enums.ItemType.Boolean:
                self.value = bool(self.value)
            elif self.typ == enums.ItemType.TextString:
                self.value = str(self.value)
            elif self.typ == enums.ItemType.ByteString:
                self.value = bytes(self.value)
            elif self.typ == enums.ItemType.DateTime:
                if not isinstance(self.value, datetime.datetime):
                    raise RuntimeError('Value must be instance of datetime.datetime')
            elif self.typ == enums.ItemType.Interval:
                if not isinstance(self.value, datetime.timedelta):
                    raise RuntimeError('Value must be instance of datetime.timedelta')

        if isinstance(self.value, types.Integer):
            if not -(1 << 31) <= self.value <= (1 << 31) - 1:
                raise RuntimeError('Integer out of range')
        elif isinstance(self.value, types.LongInteger):
            if not -(1 << 63) <= self.value <= (1 << 63) - 1:
                raise RuntimeError('LongInteger out of range')

    def __eq__(self, o):
        if o is None:
            return False
        if _enum_value(self.tag) != _enum_value(o.tag) or self.typ != o.typ:
            return False
        if self.typ == enums.ItemType.Structure:
            return all((a == b) for a, b in zip(self.value, o.value))
        return self.value == o.value

    def __ne__(self, o):
        return not self.__eq__(o)

    def __str__(self):
        s = 'TTV(tag={}, typ={}, value='.format(self.tag, self.typ)
        if self.typ == enums.ItemType.Structure:
            s += '[' + ', '.join(str(elem) for elem in self.value) + ']'
        else:
            if self.typ == enums.ItemType.ByteString:
                s += json.encode_bytestring(self.value)
            else:
                s += repr(self.value)
        s += ')'
        return s

    def __repr__(self):
        return self.__str__()

    def encode_json(self):
        return json.encode(self)

    def encode_xml(self):
        return xml.encode(self)

    def encode_ttlv(self):
        return ttlv.encode(self)

    def encodeTTLV(self):
        tt = struct.pack('>I', self.tag << 8 | self.typ.value)
        value = self.value.encode_ttlv()
        length = struct.pack('>I', len(value))
        ttlv = tt + length + value
        if len(value) % 8 != 0:
            pad_len = 8 - len(value) % 8
            pad = '\0' * pad_len
            ttlv += pad
        return ttlv
