from __future__ import (print_function, division, unicode_literals, absolute_import)

from eight import int

from kkmip import enums


def encode_int_str(val, size):
    """
    Encode an integer into a sign-extended hexadecimal string.

    Args:
        val: the integer
        size: the integer will be encoded into the smaller multiple of size bits.

    Returns:
        str: the hexadecimal-encoded int, without '0x' prefix.
    """
    bit_len = val.bit_length()
    # round up to the next multiple of size bits, considering 1 additional sign bit
    bit_len = (((bit_len + 1) + (size - 1)) // size) * size
    if val < 0:
        # compute two's complemenent of val (2^bitLen - val) with size-bit multiple size
        x = 1 << bit_len
        # val is already negative, just add it
        val += x
    return '{:0{}x}'.format(val, bit_len // 4)


def decode_int_str(val, size):
    """
    Decode a string representing an hexadecimal integer, possibly negative.

    Args:
        val: the string, e.g. "0xab01"
        size: the expected size of the integer, in bits.
            This is required to parse negative integers.

    Returns:
        int: the value represented by the string.
    """
    if val.startswith('0x'):
        val = val[2:]
    # Multiply by 4 because each char is 4 bits
    bit_len = len(val) * 4
    val = int(val, 16)
    # Special case: negative number. In this case, the number is sign-extended to a 64-bit
    # multiple, so we must check the upper bit
    if bit_len % size == 0 and (val >> (bit_len - 1)) & 1:
        val -= 1 << val.bit_length()
    return val


def decode_integer_mask(tag, name_list):
    """
    Decode a string representation of an integer mask.

    Args:
        tag (enums.Tag): the tag of the mask being decoded.
        name_list (list of str): the list of the items in the mask, e.g. ['Encrypt', '0x00000001']

    Returns:
        int: the final mask value.
    """
    enum_cls = getattr(enums, tag.name, None)
    if enum_cls is None:
        raise RuntimeError('Error decoding integer mask: '
                           'could not find enumeration class for {}'.format(tag))
    val = 0
    for name in name_list:
        if name.startswith('0x'):
            val |= int(name, 16)
        else:
            e = getattr(enum_cls, name, None)
            if e is None:
                raise RuntimeError('Error decoding integer mask: '
                                   'could not find enumeration value for {}'.format(name))
            val |= e.value
    return val
