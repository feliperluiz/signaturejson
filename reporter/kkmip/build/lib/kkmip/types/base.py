from __future__ import (print_function, division, unicode_literals, absolute_import)

from kkmip.types import encoding
from eight import range

MULTI = 1
SINGLE = 2

OPTIONAL = 1
REQUIRED = 2
MAYBE_REQUIRED = 3


class KmipObject(object):
    """
    KmipObject is the superclass of all KMIP type classes.
    """
    TAG = None
    FIELDS = None

    def __init__(self):
        # This was commented out because it also checks for required fields when reading
        # the server response. It seems better to return to the client whatever the server returned
        # instead of raising an exception.
        # The required fields are also checked on encoding, which seems good enough.
        #
        # TODO: decide the best approach and remove this if not needed
        #
        # for field_desc in self.FIELDS:
        #     field_val = getattr(self, field_desc[0])
        #     if field_val is None and field_desc[3] == REQUIRED:
        #         raise RuntimeError('Required field not specified: {}'.format(field_desc[0]))
        pass

    def encode(self):
        """
        Encode this instance as a TTV tree.

        Returns:
            kkmip.ttv.TTV: the root of the TTV tree.
        """
        return encoding.encode(self)

    def __str__(self):
        fields = []
        for name, tag, multi, required in self.FIELDS:
            value = getattr(self, name, None)
            fields.append('{}={}'.format(name, repr(value)))
        return '{}({})'.format(self.TAG.name, ', '.join(fields))
    __repr__ = __str__

    def __eq__(self, other):
        if other is None:
            return False
        if self.TAG != other.TAG or self.FIELDS != other.FIELDS:
            return False
        for name, tag, multi, required in self.FIELDS:
            self_value = getattr(self, name, None)
            other_value = getattr(other, name, None)
            if self_value != other_value:
                return False
        return True

    def __ne__(self, other):
        return not self.__eq__(other)


class RequestPayload(KmipObject):
    """
    RequestPayload is the superclass of all KMIP Request Payloads.
    """
    OPERATION = None


class ResponsePayload(KmipObject):
    """
    ResponsePayload is the superclass of all KMIP Response Payloads.
    """
    OPERATION = None


class AttributeValue(KmipObject):
    """
    Attribute is the superclass of all KMIP attribute value classes.
    """


class ManagedObject(KmipObject):
    """
    ManagedObject is the superclass of all KMIP managed object classes.
    """
