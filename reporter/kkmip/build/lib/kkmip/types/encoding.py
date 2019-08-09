"""
The encoding module is responsible for encoding KMIP objects into TTV trees and the reverse
decoding.

It is a internal module; call KmipObject.encode() or kkmip.types.decode instead.

"""
from __future__ import (print_function, division, unicode_literals, absolute_import)

import inspect
import itertools
import re

from kkmip import enums
from kkmip import ttv
from kkmip.types import maps


def _normalize(name):
    # 1. Replace brackets with space
    noBrackets = re.sub('[()]', ' ', name)
    # 2. replace \W with space if followed by letter, lower
    nonWordToSpace = re.sub('\W([A-Za-z][a-z])', r' \1', noBrackets)
    # 3. non-word to underscore
    words = [re.sub('\W', '_', s) for s in nonWordToSpace.split()]
    # 4. move numbers to end of first word
    words[0] = re.sub('^(\d+)(.*)', r'\2\1', words[0])
    # 5. captialize first letter of each word
    words = [re.sub('^.', s[0].upper(), s) for s in words]
    # 6. concatenate
    enumNameCamel = ''.join(words)
    return enumNameCamel


def _build_tag_class_map():
    """
    Build a KMIP tag -> list of Python classes map used for decoding.

    Returns:
        the map
    """
    d = {}
    from kkmip import types
    for name, value in inspect.getmembers(types, inspect.isclass):
        if value.__module__ == 'kkmip.types':
            d.setdefault(value.TAG, []).append(value)
    return d


# It's not possible to build the map on import time since kkmip.types imports this module
# and therefore at this point it has not finished being imported; the map will return empty.
# For this reason it is lazily created when read.
_TAG_CLASS_MAP = None


def _get_single_field_by_tag(ttv_fields, tag):
    """
    Given a list of (tag, fields) as used by _get_class_for_node, return the field for the given
    tag if it is unique; otherwise raise error.

    Args:
        ttv_fields (list of (tag, list of fields)): the TTV fields
        tag (Tag): the tag to search

    Returns:
        TTV: The matching TTV field

    Raises:
        RuntimeError: if the tag has multiple fields or none

    """
    matching_fields = [elem for elem in ttv_fields if elem.tag == tag]
    if len(matching_fields) != 1:
        raise RuntimeError('BatchItem must have a single Operation value')
    field = matching_fields[0]
    return field


def _get_class_for_node(node, parents):
    """
    Return the KmipObject-subclass correspoding to the given TTV node.

    It uses the list of parents node in order to resolve ambiguous cases (e.g. RequestBatchItem and
    ResponseBatchItem both have the BatchItem tag; solved by looking at the parent's tag to see if
    it is RequestMessage or ResponseMessage.)

    Args:
        node (kkmip.ttv.TTV): the TTV node
        parents (list of kkmip.ttv.TTV): list of parents of the node, direct parent last.

    Returns:
        The correspoding KmipObject subclass.
    """
    # Lazily build the class map, see its comment
    from kkmip import types
    global _TAG_CLASS_MAP
    if _TAG_CLASS_MAP is None:
        _TAG_CLASS_MAP = _build_tag_class_map()

    cls_list = _TAG_CLASS_MAP.get(node.tag)
    if cls_list is None:
        return None
    if len(cls_list) == 1:
        return cls_list[0]
    else:
        # Ambiguous tag (multiple classes for the same tag)
        if node.tag == enums.Tag.BatchItem:
            # Check the parent tag
            if parents[-1].tag == enums.Tag.RequestMessage:
                return types.RequestBatchItem
            else:
                return types.ResponseBatchItem
        elif node.tag in (enums.Tag.RequestPayload, enums.Tag.ResponsePayload):
            # Check the Operation field in the BatchItem parent
            operation = _get_single_field_by_tag(parents[-1].value, enums.Tag.Operation).value
            # e.g. "Query" + "RequestPayload"
            cls_name = operation.name + node.tag.name
            cls = getattr(types, cls_name)
            if cls is None:
                raise RuntimeError("Unsupported type: {}".format(cls_name))
            return cls
        elif node.tag == enums.Tag.CredentialValue:
            # Check the Credential Type field in the Credential parent
            credential_type = _get_single_field_by_tag(parents[-1].value,
                                                       enums.Tag.CredentialType).value
            if credential_type == enums.CredentialType.Attestation:
                return types.AttestationCredential
            elif credential_type == enums.CredentialType.Device:
                return types.DeviceCredential
            elif credential_type == enums.CredentialType.UsernameAndPassword:
                return types.PasswordCredential
            elif credential_type == enums.CredentialType.OTP:
                return types.OTPCredential
            else:
                raise RuntimeError('Unsupported CredentialType: {}'.format(credential_type))
        elif node.tag == enums.Tag.KeyMaterial:
            # Check the Key Format Type field in the KeyBlock grandparent
            key_format_type = _get_single_field_by_tag(parents[-2].value,
                                                       enums.Tag.KeyFormatType).value
            if key_format_type in (enums.KeyFormatType.Raw, enums.KeyFormatType.Opaque,
                                   enums.KeyFormatType.PKCS_1, enums.KeyFormatType.PKCS_8,
                                   enums.KeyFormatType.ECPrivateKey):
                # These are ByteString, so no specific class for them
                return None
            else:
                # TODO: handle extension types
                cls = getattr(types, key_format_type.name)
                if cls is None:
                    raise RuntimeError("Unsupported type: {}".format(key_format_type.name))
                return cls
        else:
            raise RuntimeError('Could not find type for tag: {}', node.tag)


def _get_attribute_name(field_val):
    if isinstance(field_val, enums.Tag):
        val = maps.ATTRIBUTE_TAG_NAME_MAP.get(field_val, None)
        if val is None:
            raise RuntimeError('Invalid tag used as attribute name. Must be a tag corresponding'
                               'to an attribute type')
        return val
    return field_val


def _encode_attribute_name(attribute, field_val, field_tags):
    return encode(_get_attribute_name(field_val), field_tags)


def _encode_attribute_value(attribute, field_val, field_tags):
    attribute_name = _get_attribute_name(attribute.attribute_name)
    attribute_tag_name = _normalize(attribute_name)
    attribute_tag = getattr(enums.Tag, attribute_tag_name, None)
    if attribute_tag is None or attribute_tag not in field_tags:
        raise RuntimeError('Invalid attribute name: {}'.format(repr(attribute_name)))
    node = encode(field_val, attribute_tag)
    node.tag = enums.Tag.AttributeValue
    return node


_SPECIAL_ENCODE_FUNCTIONS = {
    (enums.Tag.Attribute, 'attribute_name'): _encode_attribute_name,
    (enums.Tag.Attribute, 'attribute_value'): _encode_attribute_value,
}


def encode(val, tag=None):
    """
    Encode a KmipObject-subclass or value into a TTV tree.

    Args:
        val (any value or instance of subclass of KmipObject): the instance to encode.
        tag (Tag or list of Tag): the tag of the value or possible tags for the value.
            Can be list since some fields can hold value of multiple tags; e.g. the "object"
            field from RegisterRequestPayload can be Certificate, SymmetricKey, etc.
    Returns:
        the TTV tree.

    """
    # This avoids a circular import
    from kkmip import types
    from kkmip.types.base import KmipObject
    tags = tag if isinstance(tag, (list, tuple)) else (tag,)
    if isinstance(val, KmipObject):
        # Check if the val tag is consistent with the given tag, if any
        if val.TAG is not None and tag is not None and val.TAG not in tags:
            raise RuntimeError(
                'Value with wrong tag provided: expected {}, got {}'.format(tag, val.TAG))
        # Encode each field according to the field specification in the class
        fields = []
        for field_name, field_tags, field_multi, field_required in val.FIELDS:
            # Get the field value from the instance (can be a list or single value)
            field_values = getattr(val, field_name)
            # If it is a single value, put into a list to ease processing
            if not isinstance(field_values, list):
                field_values = [field_values]
            elif len(field_values) > 1 and field_multi == types.SINGLE:
                raise RuntimeError('Field {} of {} not allowed to have multiple values'.
                                   format(field_name, val.TAG.name))
            if field_required == types.REQUIRED and all(val is None for val in field_values):
                raise RuntimeError('Field {} of {} is required but not value was specified'.
                                   format(field_name, val.TAG.name))
            # Encode fields
            for field_val in field_values:
                if field_val is not None:
                    fn = _SPECIAL_ENCODE_FUNCTIONS.get((val.TAG, field_name))
                    if fn:
                        fields.append(fn(val, field_val, field_tags))
                    else:
                        fields.append(encode(field_val, field_tags))
        return ttv.TTV(val.TAG, fields)
    elif tag is None:
        raise RuntimeError('Tag must be specified')
    elif len(tags) > 1:
        raise RuntimeError('Multiple allowed tags and untagged value; could not '
                           'determined which tag to use. Value = {}, tags = {}'.format(val, tag))
    else:
        if isinstance(val, enums.Enum):
            # Special case: if enum, check if it belongs to the corresponding enum of
            # any of the given tags
            for tag in tags:
                enum_cls = getattr(enums, tag.name, None)
                if type(val) is enum_cls:
                    break
            else:
                raise RuntimeError('Enumeration {} expected to belong to {}'.format(val, tag))
        typs = maps.TAG_TYPE_MAP.get(tag)
        typ = typs[0] if len(typs) == 1 else None
        # If typ is None the TTV constructor will determine from the Python type of val
        return ttv.TTV(tag, val, typ)


def _decode_attribute_value(attribute, field_values, parents, cls):
    """
    Decode the attribute_value field in the Attribute type.

    KMIP specifies that on return, the attribute_value field will have tag AttributeValue.
    However, we need the actual attribute tag (e.g. CryptograhicAlgorithm) in order to decode it.
    This functions looks at the attribute_name field of the Attribute and converts it to the
    tag which will be passed for decoding the attribute_value.

    Args:
        attribute (TTV): the TTV of the Attribute
        field_values (list of TTV): the values of the attribute_value field (should be a single item)
        parents (list of TTV): list of parents of attribute_value
        cls: the Attribute class.

    Returns:
        tuple(str, AttributeValue): 'attribute_value' and the decoded attribute value.
    """
    ttv_attribute_name = _get_single_field_by_tag(attribute.value, enums.Tag.AttributeName)
    attribute_name = _get_attribute_name(ttv_attribute_name.value)
    attribute_tag_name = _normalize(attribute_name)
    attribute_tag = getattr(enums.Tag, attribute_tag_name, None)
    allowed_attribute_tags = [desc[1] for desc in cls.FIELDS if desc[0] == 'attribute_value'][0]
    if attribute_tag is None or attribute_tag not in allowed_attribute_tags:
        raise RuntimeError('Invalid attribute name: {}'.format(repr(attribute_name)))
    if len(field_values) > 1:
        raise RuntimeError(
            'Field attribute_value of Attribute is not allowed to have multiple values')
    field_values[0].tag = attribute_tag
    return 'attribute_value', _decode(field_values[0], parents)


_SPECIAL_DECODE_FUNCTIONS = {
    (enums.Tag.Attribute, enums.Tag.AttributeValue): _decode_attribute_value,
}
"""
Map of special field decode functions, keyed by (tag of node, tag of field).
The function is called for the specified field inside the specified node.

The functions are called with:
    parent (TTV): the TTV of the node
    field_values (list of TTV): values with the field tag specified
    parents (list of TTV): parents of the field (includes "parent")
    cls: corresponding class of "parent"
"""


def _decode(node, parents=None):
    """
    Return a KmipObject-subclass tree correspoding to the given TTV tree.

    Args:
        node (TTV): the root of the TTV tree.
        parents (list of kkmip.ttv.TTV): list of parents of the node, direct parent last.

    Returns:
        KmipObject of the root.
    """
    from kkmip import types
    if parents is None:
        parents = []
    if node.typ != enums.ItemType.Structure:
        # In some cases, enumerations can't be resolved by the TTV decoder.
        # For example, an AttributeValue: since the tag is "AttributeValue", the TTV decoder
        # does not know which enum class to use. This types decoder, however, fixes this (see
        # the _decode_attribute_value function) so, at this point, we have the correct tag
        # and can finally resolve the enumeration.
        # The same applies to integer masks.
        if node.typ == enums.ItemType.Enumeration:
            enum_cls = getattr(enums, node.tag.name)
            if isinstance(node.value, ttv.UnknownEnumeration):
                return enum_cls(node.value)
            elif isinstance(node.value, ttv.UnknownEnumerationString):
                return enum_cls[node.value]
        elif node.typ == enums.ItemType.Integer:
            if isinstance(node.value, ttv.UnknownIntegerMask):
                val = ttv.decode_integer_mask(node.tag, node.value)
                return ttv.Integer(val)
        # Otherwise, the value is already OK, just return it
        return node.value
    else:
        cls = _get_class_for_node(node, parents)
        if cls is None:
            raise RuntimeError()
        # Add this node to be passed when decoding children
        parents.append(node)
        try:
            # Tag -> field name
            tag_field_name_map = {}
            # Tag -> multi-instance flag
            tag_multi_map = {}
            for field_name, tags, multi, required in cls.FIELDS:
                tags = tags if isinstance(tags, (list, tuple)) else [tags]
                for tag in tags:
                    tag_field_name_map[tag] = field_name
                    tag_multi_map[tag] = multi
            # The TTV value for a Structure is a list of TTV nodes, i.e. the structure fields.
            # Multi-instance fields are indicated by multiple fields with the same tag.
            # Here we group these field as a list of (tag, [list of TTV nodes]).
            # TODO: enforce the order of the fields
            fields = [(k, list(g)) for k, g in
                      itertools.groupby(node.value, lambda n: n.tag)]
            # The arguments that will be passed to the class constructor
            kwargs = {}
            for tag, field_values in fields:
                fn = _SPECIAL_DECODE_FUNCTIONS.get((node.tag, tag))
                if fn is not None:
                    field_name, value = fn(node, field_values, parents, cls)
                    kwargs[field_name] = value
                else:
                    field_name = tag_field_name_map.get(tag)
                    if field_name is None:
                        raise RuntimeError("Could not find which field of {} "
                                           "should receive the value with tag {}: {}".format(
                            node.tag, tag, field_values))
                    if tag_multi_map[tag] == types.SINGLE and len(field_values) > 1:
                        raise RuntimeError('Field {} of {} is not allowed to '
                                           'have multiple values'.format(node.tag, tag))
                    # TODO: should we check the REQUIRE flag?
                    # Seems overkill to raise an exception because of it and it makes it harder to find
                    # what is going on if the server does not send a required field.
                    # One possibility is to give a warning of some sort.
                    kwargs[field_name] = [_decode(elem, parents) for elem in field_values]
                    # For single-instance fields, pass the value and not a one-element list
                    if tag_multi_map[tag] == types.SINGLE:
                        kwargs[field_name] = kwargs[field_name][0]
            # Instantiate with the decoded arguments
            return cls(**kwargs)
        finally:
            # Remove this node
            parents.pop()


def decode(node):
    """
    Return a KmipObject-subclass tree correspoding to the given TTV tree.

    Args:
        node (TTV): the root of the TTV tree.

    Returns:
        KmipObject of the root.
    """
    return _decode(node)
