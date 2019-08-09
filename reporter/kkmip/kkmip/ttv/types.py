from __future__ import (print_function, division, unicode_literals, absolute_import)

from eight import int, str


class Integer(int):
    """
    A KMIP Integer.

    Used to avoid ambiguity since all KMIP integer types can be Python ints.
    """


class UnknownIntegerMask(list):
    """
    A KMIP Mask Integer.

    One of the mask types (e.g. CryptographicUsageMask), as a list of strings with the names
    of the masks (e.g. ["Sign", "Encrypt"]).
    """


class LongInteger(int):
    """
    A KMIP LongInteger.

    Used to avoid ambiguity since all KMIP integer types can be Python ints.
    """


class BigInteger(int):
    """
    A KMIP BigInteger.

    Used to avoid ambiguity since all KMIP integer types can be Python ints.
    """


class UnknownEnumeration(int):
    """
    A KMIP Enumeration.

    Used to represent non-standard enums which are not present in the enum package.
    """


class UnknownEnumerationString(str):
    """
    A KMIP Enumeration as a string.

    Used to represent non-standard enums which are not present in the enum package.
    """
