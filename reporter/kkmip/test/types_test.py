# coding=utf-8
from __future__ import (print_function, division, unicode_literals, absolute_import)

import json

import pytest

from kkmip import enums
from kkmip import ttv
from kkmip import types

request_kmip_tree = types.RequestMessage(
    types.RequestHeader(
        protocol_version=types.ProtocolVersion(1, 3),
        batch_count=1,
    ),
    [
        types.RequestBatchItem(
            operation=enums.Operation.Query,
            request_payload=types.QueryRequestPayload(
                [
                    enums.QueryFunction.QueryObjects,
                    enums.QueryFunction.QueryServerInformation,
                ]
            ),
        ),
    ],
)

request_ttv_tree = ttv.TTV(
    tag=enums.Tag.RequestMessage,
    value=[
        ttv.TTV(
            tag=enums.Tag.RequestHeader,
            value=[
                ttv.TTV(
                    tag=enums.Tag.ProtocolVersion,
                    value=[
                        ttv.TTV(enums.Tag.ProtocolVersionMajor, 1),
                        ttv.TTV(enums.Tag.ProtocolVersionMinor, 3),
                    ]
                ),
                ttv.TTV(tag=enums.Tag.BatchCount, value=1)
            ]
        ),
        ttv.TTV(
            tag=enums.Tag.BatchItem,
            value=[
                ttv.TTV(tag=enums.Tag.Operation, value=enums.Operation.Query),
                ttv.TTV(
                    tag=enums.Tag.RequestPayload,
                    value=[
                        ttv.TTV(tag=enums.Tag.QueryFunction,
                                value=enums.QueryFunction.QueryObjects),
                        ttv.TTV(tag=enums.Tag.QueryFunction,
                                value=enums.QueryFunction.QueryServerInformation),
                    ]
                )
            ]
        )
    ]
)

credential_kmip_tree = types.Credential(
    credential_type=enums.CredentialType.UsernameAndPassword,
    credential_value=types.PasswordCredential(
        username='user',
        password='pass'
    )
)

credential_ttv_tree = ttv.TTV(
    tag=enums.Tag.Credential,
    value=[
        ttv.TTV(tag=enums.Tag.CredentialType, value=enums.CredentialType.UsernameAndPassword),
        ttv.TTV(
            tag=enums.Tag.CredentialValue,
            value=[
                ttv.TTV(tag=enums.Tag.Username, value='user'),
                ttv.TTV(tag=enums.Tag.Password, value='pass'),
            ]
        )
    ]
)

key_block_kmip_tree = types.KeyBlock(
    key_format_type=enums.KeyFormatType.TransparentRSAPublicKey,
    key_value=types.KeyValue(
        key_material=types.TransparentRSAPublicKey(
            modulus=ttv.BigInteger(1111111111111111111),
            public_exponent=0x10001,
        ),
    ),
    cryptographic_algorithm=enums.CryptographicAlgorithm.RSA,
)

key_block_ttv_tree = ttv.TTV(
    tag=enums.Tag.KeyBlock,
    value=[
        ttv.TTV(enums.Tag.KeyFormatType, enums.KeyFormatType.TransparentRSAPublicKey),
        ttv.TTV(
            tag=enums.Tag.KeyValue,
            value=[
                ttv.TTV(
                    tag=enums.Tag.KeyMaterial,
                    value=[
                        ttv.TTV(tag=enums.Tag.Modulus, value=ttv.BigInteger(1111111111111111111)),
                        ttv.TTV(tag=enums.Tag.PublicExponent, value=ttv.BigInteger(0x10001)),
                    ]
                )
            ]
        ),
        ttv.TTV(tag=enums.Tag.CryptographicAlgorithm, value=enums.CryptographicAlgorithm.RSA)
    ]
)


def test_compare():
    h1 = types.RequestHeader(
        protocol_version=types.ProtocolVersion(1, 3),
        batch_count=1,
    )
    h2 = types.RequestHeader(
        protocol_version=types.ProtocolVersion(1, 3),
        batch_count=1,
    )
    h3 = types.RequestHeader(
        protocol_version=types.ProtocolVersion(1, 4),
        batch_count=1,
    )
    h4 = types.RequestHeader(
        protocol_version=types.ProtocolVersion(1, 4),
        batch_count=2,
    )
    h5 = types.ProtocolVersion(1, 4)
    assert h1 == h2
    assert h1 != h3
    assert h2 != h3
    assert h1 != h4
    assert h1 != h5


def test_encoding():
    got_ttv_tree = request_kmip_tree.encode()
    assert got_ttv_tree == request_ttv_tree
    got_ttv_tree = credential_kmip_tree.encode()
    assert got_ttv_tree == credential_ttv_tree
    got_ttv_tree = key_block_kmip_tree.encode()
    print(got_ttv_tree)
    print(key_block_ttv_tree)
    assert got_ttv_tree == key_block_ttv_tree


def test_decoding():
    got_kmip_tree = types.decode(request_ttv_tree)
    assert got_kmip_tree == request_kmip_tree
    got_kmip_tree = types.decode(credential_ttv_tree)
    assert got_kmip_tree == credential_kmip_tree
    got_kmip_tree = types.decode(key_block_ttv_tree)
    assert got_kmip_tree == key_block_kmip_tree


def test_required():
    # Missing Operation (required), Unique Batch ID (maybe required) and Message Extension (optional)
    item = types.RequestBatchItem(
        request_payload=types.QueryRequestPayload(
            [
                enums.QueryFunction.QueryObjects,
                enums.QueryFunction.QueryServerInformation,
            ]
        ),
    )
    with pytest.raises(RuntimeError):
        item.encode()

    # Missing Unique Batch ID (maybe required) and Message Extension (optional)
    item = types.RequestBatchItem(
        operation=enums.Operation.Query,
        request_payload=types.QueryRequestPayload(
            [
                enums.QueryFunction.QueryObjects,
                enums.QueryFunction.QueryServerInformation,
            ]
        ),
    )
    item.encode()


def test_attribute_value():
    template_attribute = types.TemplateAttribute(
        attribute_list=[
            types.Attribute(
                attribute_name='Cryptographic Algorithm',
                attribute_value=enums.CryptographicAlgorithm.AES
            )
        ]
    )
    node = template_attribute.encode()
    assert node.value[0].value[1].value == enums.CryptographicAlgorithm.AES
    assert node == ttv.TTV(enums.Tag.TemplateAttribute, [
        ttv.TTV(enums.Tag.Attribute, [
            ttv.TTV(enums.Tag.AttributeName, 'Cryptographic Algorithm'),
            ttv.TTV(enums.Tag.AttributeValue, enums.CryptographicAlgorithm.AES),
        ])
    ])

    attr = types.decode(node)
    assert (attr.attribute_list[0].attribute_name
            == template_attribute.attribute_list[0].attribute_name)
    assert (attr.attribute_list[0].attribute_value
            == template_attribute.attribute_list[0].attribute_value)
    assert attr == template_attribute

    template_attribute = types.TemplateAttribute(
        attribute_list=[
            types.Attribute(
                attribute_name=enums.Tag.CryptographicAlgorithm,
                attribute_value=enums.CryptographicAlgorithm.AES
            )
        ]
    )
    node = template_attribute.encode()
    assert node.value[0].value[0].value == 'Cryptographic Algorithm'
    assert node.value[0].value[1].value == enums.CryptographicAlgorithm.AES

    attr = types.decode(node)
    assert (attr.attribute_list[0].attribute_value
            == template_attribute.attribute_list[0].attribute_value)


def test_attribute_value_decode():
    node = ttv.TTV(enums.Tag.Attribute, [
        ttv.TTV(enums.Tag.AttributeName, 'Cryptographic Algorithm'),
        ttv.TTV(enums.Tag.AttributeValue, enums.CryptographicAlgorithm.AES),
    ])
    attr = types.decode(node)
    want = types.Attribute(
        attribute_name='Cryptographic Algorithm',
        attribute_value=enums.CryptographicAlgorithm.AES
    )
    assert attr == want


def test_attribute_value_decode_json():
    want = types.Attribute(
        attribute_name='Cryptographic Algorithm',
        attribute_value=enums.CryptographicAlgorithm.AES
    )
    js = {
        "tag": "Attribute",
        "value": [
            {"tag": "AttributeName", "type": "TextString", "value": "Cryptographic Algorithm"},
            {"tag": "AttributeValue", "type": "Enumeration", "value": "AES"},
        ]
    }
    attr = types.decode(ttv.decode_json(js))
    assert attr == want


def test_attribute_value_decode_xml():
    want = types.Attribute(
        attribute_name='Cryptographic Algorithm',
        attribute_value=enums.CryptographicAlgorithm.AES
    )
    xml = '''
    <Attribute>
        <AttributeName type="TextString" value="Cryptographic Algorithm" />
        <AttributeValue type="Enumeration" value="AES" />
    </Attribute>
    '''.encode('utf-8')
    attr = types.decode(ttv.decode_xml(ttv.decode_xml_from_string(xml)))
    assert attr == want


def test_attribute_value_decode2():
    node = ttv.TTV(enums.Tag.Attribute, [
        ttv.TTV(enums.Tag.AttributeName, 'Cryptographic Parameters'),
        ttv.TTV(enums.Tag.AttributeValue, [
            ttv.TTV(enums.Tag.BlockCipherMode, enums.BlockCipherMode.CTR),
        ]),
    ])
    attr = types.decode(node)
    want = types.Attribute(
        attribute_name='Cryptographic Parameters',
        attribute_value=types.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CTR,
        ),
    )
    assert attr == want


def test_mask():
    attr = types.Attribute(
        attribute_name=enums.Tag.CryptographicUsageMask,
        attribute_value=enums.CryptographicUsageMask.Encrypt | enums.CryptographicUsageMask.Decrypt,
    )
    node = attr.encode()
    assert node.value[1].tag == enums.Tag.AttributeValue
    assert node.value[1].typ == enums.ItemType.Integer
    assert node.value[1].value == (enums.CryptographicUsageMask.Encrypt.value |
                                   enums.CryptographicUsageMask.Decrypt.value)


def test_str():
    payload = types.EncryptRequestPayload(data=b'\x11')
    print(payload)
