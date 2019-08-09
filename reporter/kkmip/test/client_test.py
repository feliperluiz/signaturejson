from __future__ import (
    print_function,
    division,
    unicode_literals,
    absolute_import)

import pytest
import os

# module for activation mode
import datetime
import iso8601

# Sleep
import time

# module for get hex py3 and py2
import binascii

# module to be tested
from kkmip import client
from kkmip import enums
from kkmip import ttv
from kkmip import types
from kkmip.error import KmipError

# Options
host_option = pytest.config.getoption("--host")
httpsPort_option = pytest.config.getoption("--httpsPort")
cacert_option = pytest.config.getoption("--cacert", False)
cert_option = pytest.config.getoption("--cert")
key_option = pytest.config.getoption("--key")
unix_option = pytest.config.getoption("--unixSocket")

# Skip server test, case it hasnt passed the kmip server arguments
server_test = pytest.mark.skipif(
    not (
        (host_option and httpsPort_option and cert_option and key_option) or unix_option),
    reason="Must have kmip server parameters (host, httpsPort, cert and key) or unixSocket flag")

# Skip test when it is  unixSocket
server_test_no_unix_socket = pytest.mark.skipif(
    unix_option,
    reason="Avoided test with unix socket. Test without unixSocket flag"
)


# Data of the file used to test SE App
with open("test/example_create_app.py", "rb") as f:
    BYTE_APP_DATA = f.read()

# Data to test hash function
with open("test/DONT_CHANGE.hash_test", "rb") as f:
    HASH_BYTES = f.read()


# Spec
TTLV_PORT = 5696

# Protocols to be tested
TESTED_PROTOCOLS = []
if host_option and httpsPort_option and cacert_option and cert_option and key_option:
    # External protocols
    TESTED_PROTOCOLS += [
        client.Protocol.HTTPS_XML,
        client.Protocol.HTTPS_TTLV,
        client.Protocol.HTTPS_JSON,
        client.Protocol.TTLV,  # pure tls
    ]

if unix_option:
    # Internal protocol
    TESTED_PROTOCOLS += [
        client.Protocol.UNIX_TTLV,
        client.Protocol.UNIX_JSON,
        client.Protocol.UNIX_XML,

    ]


# SE App test
TESTED_APP_NAME = [
    "example_create_app.py",
]

# This example is used by the documentation. Don't change the function name.


@server_test
def test_example(host, httpsPort, cacert, cert, key, unixSocket):
    proto = client.Protocol.HTTPS_JSON
    if unixSocket:
        proto = client.Protocol.UNIX_JSON

    c = client.Client(host, httpsPort, proto, cacert, (cert, key))
    payload = types.QueryRequestPayload([
        enums.QueryFunction.QueryOperations,
        enums.QueryFunction.QueryServerInformation,
    ])
    r = c.post(payload)
    print(r.operation_list)


@server_test
@pytest.mark.parametrize("protocol", TESTED_PROTOCOLS)
def test_server_query(host, httpsPort, protocol, cacert, cert, key):
    c = client_instance(
        host,
        httpsPort,
        TTLV_PORT,
        protocol,
        cacert,
        cert,
        key)

    payload = types.QueryRequestPayload([
        enums.QueryFunction.QueryOperations,
        enums.QueryFunction.QueryServerInformation,
        # Just an example of how to pass an enum if it is not listed in our enums
        # (even though this particular value is there)
        ttv.UnknownEnumeration(2),
    ])
    b = client.Batch(payload)
    r = c.post_batch(b)
    assert r
    assert isinstance(r[0], types.QueryResponsePayload)
    assert r[0].operation_list

    r = c.post(payload)
    assert r.operation_list

    request = types.RequestMessage(
        types.RequestHeader(
            protocol_version=types.ProtocolVersion(1, 2),
            batch_count=1,
        ),
        [
            types.RequestBatchItem(
                operation=enums.Operation.Query,
                request_payload=payload
            ),
        ],
    )
    response = c.post_request_message(request)
    assert response
    assert response.response_header
    assert response.batch_item_list
    assert response.batch_item_list[0]
    assert response.batch_item_list[0].response_payload


@server_test
@pytest.mark.parametrize("protocol", TESTED_PROTOCOLS)
def test_server_error(host, httpsPort, protocol, cacert, cert, key):
    c = client_instance(
        host,
        httpsPort,
        TTLV_PORT,
        protocol,
        cacert,
        cert,
        key)

    payload = types.GetRequestPayload(
        unique_identifier='non existent identifier'
    )

    b = client.Batch(payload)
    r = c.post_batch(b)
    assert r
    assert isinstance(r[0], KmipError)
    assert r[0].result_status == enums.ResultStatus.OperationFailed
    assert r[0].result_reason == enums.ResultReason.ItemNotFound

    with pytest.raises(KmipError):
        c.post(payload)


@server_test
@pytest.mark.parametrize("protocol", TESTED_PROTOCOLS)
def test_server_register_key(host, httpsPort, protocol, cacert, cert, key):
    clt = client_instance(
        host,
        httpsPort,
        TTLV_PORT,
        protocol,
        cacert,
        cert,
        key)

    name_test = "import_key_" + str(protocol)

    # Create attributes
    name_a = types.Attribute("Name", 0, types.Name(
        name_test, enums.NameType.UninterpretedTextString))
    algo_a = types.Attribute(
        "Cryptographic Algorithm",
        0,
        enums.CryptographicAlgorithm.AES)
    length_a = types.Attribute("Cryptographic Length", 0, 256)
    usage_a = types.Attribute(
        "Cryptographic Usage Mask",
        0,
        enums.CryptographicUsageMask.Encrypt.value | enums.CryptographicUsageMask.Decrypt.value)

    # Create cryptographic parameters for attribute
    crypt_param = types.CryptographicParameters()
    crypt_param.block_cipher_mode = enums.BlockCipherMode.CBC
    crypt_param.padding_method = enums.PaddingMethod.PKCS5
    crypt_param.hashing_algorithm = enums.HashingAlgorithm.SHA_256
    crypt_param.cryptographic_algorithm = enums.CryptographicAlgorithm.AES
    crypt_param.random_iv = True

    # Create attribute for crypto parameters
    param_a = types.Attribute("Cryptographic Parameters", 0, crypt_param)

    # Create attribute template with above attr
    att_template = types.TemplateAttribute(
        None, [name_a, algo_a, length_a, usage_a, param_a])

    # Symmetric key value
    key = "3425b140b5938ddf1b4328a69f98dc50296d266c8a236a1c3ef775f047009a98"
    key_data = binascii.a2b_hex(key)
    key_mat = types.TransparentSymmetricKey(key_data)

    # Key Information
    symm_block = types.KeyBlock()
    symm_block.key_format_type = enums.KeyFormatType.TransparentSymmetricKey
    symm_block.cryptographic_algorithm = enums.CryptographicAlgorithm.AES
    symm_block.cryptographic_length = 256
    symm_block.key_value = types.KeyValue(key_mat, None)

    # Object to be imported
    symm_key = types.SymmetricKey(symm_block)

    # Create payload
    payload = types.RegisterRequestPayload()
    payload.object_type = enums.ObjectType.SymmetricKey
    payload.template_attribute = att_template
    payload.object = symm_key
    b = client.Batch(payload)

    # Post
    r = clt.post_batch(b)

    # Verify register
    assert r
    assert isinstance(r[0], types.RegisterResponsePayload)
    assert r[0].unique_identifier
    u_id = r[0].unique_identifier

    # Verify by locating
    r = locate_obj([name_a, types.Attribute(
        "Object Type", 0, enums.ObjectType.SymmetricKey)], clt)
    assert r
    assert isinstance(r[0], types.LocateResponsePayload)
    assert r[0].unique_identifier_list[0]
    assert u_id == r[0].unique_identifier_list[0]

    # Verify destroy
    r = destroy_obj(u_id, clt)
    assert not isinstance(r[0], KmipError)


@server_test
@pytest.mark.parametrize("protocol", TESTED_PROTOCOLS)
def test_server_create_and_mode_key(
        host,
        httpsPort,
        protocol,
        cacert,
        cert,
        key):
    clt = client_instance(
        host,
        httpsPort,
        TTLV_PORT,
        protocol,
        cacert,
        cert,
        key)

    name_test = "create_key_" + str(protocol)

    # Create attributes
    name_a = types.Attribute(enums.Tag.Name, 0, types.Name(
        name_test, enums.NameType.UninterpretedTextString))
    algo_a = types.Attribute(
        "Cryptographic Algorithm",
        0,
        enums.CryptographicAlgorithm.AES)
    length_a = types.Attribute("Cryptographic Length", 0, 256)
    usage_a = types.Attribute(
        "Cryptographic Usage Mask",
        0,
        enums.CryptographicUsageMask.Encrypt.value | enums.CryptographicUsageMask.Decrypt.value)

    # Create cryptographic parameters for attribute
    crypt_param = types.CryptographicParameters()
    crypt_param.block_cipher_mode = enums.BlockCipherMode.CBC
    crypt_param.padding_method = enums.PaddingMethod.PKCS5
    crypt_param.hashing_algorithm = enums.HashingAlgorithm.SHA_256
    crypt_param.cryptographic_algorithm = enums.CryptographicAlgorithm.AES
    crypt_param.random_iv = True

    # Create attribute for crypto parameters
    param_a = types.Attribute(
        enums.Tag.CryptographicParameters, 0, crypt_param)

    # Create attribute template with above attr
    att_template = types.TemplateAttribute(
        None, [name_a, algo_a, length_a, usage_a, param_a])

    # Create payload
    payload = types.CreateRequestPayload()
    payload.object_type = enums.ObjectType.SymmetricKey
    payload.template_attribute = att_template
    b = client.Batch(payload)

    # Post
    r = clt.post_batch(b)

    # Verify created key
    assert r
    assert isinstance(r[0], types.CreateResponsePayload)
    assert r[0].unique_identifier
    assert r[0].object_type == enums.ObjectType.SymmetricKey
    u_id = r[0].unique_identifier

    # Verify activate key
    r = activate_obj(u_id, clt)
    assert not isinstance(r[0], KmipError)
    assert r[0].unique_identifier == u_id

    # Try destroy, but it should fail (obj on activate mode)
    r = destroy_obj(u_id, clt)
    assert isinstance(r[0], KmipError)

    # Verify deactivate key
    r = deactivate_obj(u_id, clt)
    assert not isinstance(r[0], KmipError)
    assert r[0].unique_identifier == u_id

    # destroy deactivated key
    r = destroy_obj(r[0].unique_identifier, clt)
    assert not isinstance(r[0], KmipError)


@server_test
@pytest.mark.parametrize("protocol", TESTED_PROTOCOLS)
def test_server_get_key(host, httpsPort, protocol, cacert, cert, key):
    clt = client_instance(
        host,
        httpsPort,
        TTLV_PORT,
        protocol,
        cacert,
        cert,
        key)

    # Create attributes
    name_test = "get_key_" + str(protocol)
    name_a = types.Attribute(enums.Tag.Name, 0, types.Name(
        name_test, enums.NameType.UninterpretedTextString))
    algo_a = types.Attribute(
        "Cryptographic Algorithm",
        0,
        enums.CryptographicAlgorithm.AES)
    length_a = types.Attribute("Cryptographic Length", 0, 256)
    usage_a = types.Attribute(
        "Cryptographic Usage Mask",
        0,
        enums.CryptographicUsageMask.Encrypt.value | enums.CryptographicUsageMask.Decrypt.value)
    crypt_param = types.CryptographicParameters()
    crypt_param.block_cipher_mode = enums.BlockCipherMode.CBC
    crypt_param.padding_method = enums.PaddingMethod.PKCS5
    crypt_param.hashing_algorithm = enums.HashingAlgorithm.SHA_256
    crypt_param.cryptographic_algorithm = enums.CryptographicAlgorithm.AES
    crypt_param.random_iv = True
    param_a = types.Attribute("Cryptographic Parameters", None, crypt_param)
    att_template = types.TemplateAttribute(
        None, [name_a, algo_a, length_a, usage_a, param_a])

    # Create payload
    payload = types.CreateRequestPayload()
    payload.object_type = enums.ObjectType.SymmetricKey
    payload.template_attribute = att_template
    b = client.Batch(payload)
    r = clt.post_batch(b)

    # Verify created key
    assert r
    assert isinstance(r[0], types.CreateResponsePayload)
    assert r[0].unique_identifier
    assert r[0].object_type == enums.ObjectType.SymmetricKey
    u_id = r[0].unique_identifier

    # Get attribute
    r = get_attributes(u_id, ["Cryptographic Parameters"], clt)
    assert r
    assert isinstance(r[0], types.GetAttributesResponsePayload)
    assert r[0].unique_identifier == u_id
    assert r[0].attribute_list
    assert r[0].attribute_list[0].attribute_name == param_a.attribute_name
    assert isinstance(
        r[0].attribute_list[0].attribute_value,
        types.CryptographicParameters)
    assert r[0].attribute_list[
        0].attribute_value.block_cipher_mode == crypt_param.block_cipher_mode
    assert r[0].attribute_list[
        0].attribute_value.padding_method == crypt_param.padding_method
    assert r[0].attribute_list[
        0].attribute_value.hashing_algorithm == crypt_param.hashing_algorithm
    assert r[0].attribute_list[
        0].attribute_value.cryptographic_algorithm == crypt_param.cryptographic_algorithm
    assert r[0].attribute_list[
        0].attribute_value.random_iv == crypt_param.random_iv

    # Modify attribute crypt parameters (hash, block and padding)
    crypt_mod_param = types.CryptographicParameters()
    crypt_mod_param.block_cipher_mode = enums.BlockCipherMode.CTR
    crypt_mod_param.padding_method = enums.PaddingMethod.OAEP
    crypt_mod_param.hashing_algorithm = enums.HashingAlgorithm.SHA_512
    r = modify_attribute(
        u_id,
        types.Attribute(
            enums.Tag.CryptographicParameters,
            0,
            crypt_mod_param),
        clt)
    assert r
    assert isinstance(r[0], types.ModifyAttributeResponsePayload)
    assert r[0].unique_identifier == u_id
    assert isinstance(r[0].attribute, types.Attribute)
    assert r[
        0].attribute.attribute_value.block_cipher_mode != crypt_param.block_cipher_mode
    assert r[0].attribute.attribute_value.padding_method != crypt_param.padding_method
    assert r[
        0].attribute.attribute_value.hashing_algorithm != crypt_param.hashing_algorithm

    # Delete attribute
    payload = types.DeleteAttributeRequestPayload(
        u_id, "Cryptographic Parameters", 0)
    b = client.Batch(payload)
    r = clt.post_batch(b)
    assert r
    assert isinstance(r[0], types.DeleteAttributeResponsePayload)
    assert r[0].unique_identifier == u_id

    # Verify by checking that the removeded attribute is no more there
    r = get_attributes(u_id, ["Cryptographic Parameters"], clt)
    assert r
    assert isinstance(r[0], types.GetAttributesResponsePayload)
    assert r[0].unique_identifier == u_id
    assert r[0].attribute_list is None

    # Add attribute
    payload = types.AddAttributeRequestPayload(u_id, param_a)
    b = client.Batch(payload)
    r = clt.post_batch(b)
    assert r
    assert isinstance(r[0], types.AddAttributeResponsePayload)
    assert r[0].unique_identifier == u_id

    # Verify added attribute by checking that the added attribute is there
    r = get_attributes(u_id, ["Cryptographic Parameters"], clt)
    assert r
    assert isinstance(r[0], types.GetAttributesResponsePayload)
    assert r[0].unique_identifier == u_id
    assert r[0].attribute_list
    assert r[0].attribute_list[0].attribute_name == param_a.attribute_name
    assert isinstance(
        r[0].attribute_list[0].attribute_value,
        types.CryptographicParameters)
    assert r[0].attribute_list[
        0].attribute_value.block_cipher_mode == crypt_param.block_cipher_mode
    assert r[0].attribute_list[
        0].attribute_value.padding_method == crypt_param.padding_method
    assert r[0].attribute_list[
        0].attribute_value.hashing_algorithm == crypt_param.hashing_algorithm
    assert r[0].attribute_list[
        0].attribute_value.cryptographic_algorithm == crypt_param.cryptographic_algorithm
    assert r[0].attribute_list[
        0].attribute_value.random_iv == crypt_param.random_iv

    # destroy deactivated key
    r = destroy_obj(u_id, clt)
    assert not isinstance(r[0], KmipError)

# Params for encrypt/decrypt
ENC_DEC_PARAMS = []
# tested size for be encrypted/decrypted
DATA_SIZE = [0, 1, 2187, 100000, 1000000]
for size in DATA_SIZE:
    ENC_DEC_PARAMS = ENC_DEC_PARAMS + \
        [tuple([elem] + [size]) for elem in TESTED_PROTOCOLS]


@server_test
@pytest.mark.parametrize("protocol, size", ENC_DEC_PARAMS)
def test_server_encrypt_decrypt(
        host,
        httpsPort,
        protocol,
        size,
        cacert,
        cert,
        key):
    clt = client_instance(
        host,
        httpsPort,
        TTLV_PORT,
        protocol,
        cacert,
        cert,
        key)

    # Ramdom data
    data = os.urandom(size)

    # Create key on activated mode
    algo_a = types.Attribute(
        "Cryptographic Algorithm",
        0,
        enums.CryptographicAlgorithm.AES)
    length_a = types.Attribute("Cryptographic Length", 0, 256)
    usage_a = types.Attribute(
        "Cryptographic Usage Mask",
        0,
        enums.CryptographicUsageMask.Encrypt.value | enums.CryptographicUsageMask.Decrypt.value)
    active_a = types.Attribute(
        "Activation Date", 0, datetime.datetime.now(
            iso8601.UTC))  # activate key now
    crypt_param = types.CryptographicParameters()
    crypt_param.cryptographic_algorithm = enums.CryptographicAlgorithm.AES
    crypt_param.block_cipher_mode = enums.BlockCipherMode.CBC
    crypt_param.padding_method = enums.PaddingMethod.PKCS5
    crypt_param.hashing_algorithm = enums.HashingAlgorithm.SHA_256
    crypt_param.random_iv = True
    param_a = types.Attribute(
        enums.Tag.CryptographicParameters, 0, crypt_param)
    att_template = types.TemplateAttribute(
        None, [algo_a, length_a, usage_a, active_a, param_a])
    payload = types.CreateRequestPayload()
    payload.object_type = enums.ObjectType.SymmetricKey
    payload.template_attribute = att_template
    b = client.Batch(payload)
    r = clt.post_batch(b)

    # Verify symm key created
    assert r
    assert isinstance(r[0], types.CreateResponsePayload)
    assert r[0].unique_identifier
    assert r[0].object_type == enums.ObjectType.SymmetricKey
    u_id = r[0].unique_identifier

    # Encrypt data
    en_payload = types.EncryptRequestPayload()
    en_payload.unique_identifier = u_id
    en_payload.data = data
    b = client.Batch(en_payload)
    r = clt.post_batch(b)

    # Verify encryption
    assert r
    assert isinstance(r[0], types.EncryptResponsePayload)
    assert r[0].data
    assert r[0].iv_counter_nonce
    assert r[0].unique_identifier == u_id

    # Decrypt data
    de_payload = types.DecryptRequestPayload()
    de_payload.unique_identifier = u_id
    de_payload.data = r[0].data
    de_payload.iv_counter_nonce = r[0].iv_counter_nonce
    b = client.Batch(de_payload)
    r = clt.post_batch(b)

    # Verify decryption
    assert r
    assert isinstance(r[0], types.DecryptResponsePayload)
    if size <= 0:
        assert r[0].data is None
        assert r[0].unique_identifier == u_id
    else:
        assert r[0].data
        assert r[0].data == data

    # Deactivate key for destroying
    r = deactivate_obj(u_id, clt)
    assert not isinstance(r[0], KmipError)
    assert r[0].unique_identifier == u_id

    # Verify destroy key
    r = destroy_obj(u_id, clt)
    assert not isinstance(r[0], KmipError)
    assert r[0].unique_identifier == u_id


@server_test
@pytest.mark.parametrize("protocol", TESTED_PROTOCOLS)
def test_server_asymmetric(host, httpsPort, protocol, cacert, cert, key):
    clt = client_instance(
        host,
        httpsPort,
        TTLV_PORT,
        protocol,
        cacert,
        cert,
        key)
    name_test = "asymmetric_test_" + str(protocol)

    # Create key pair on deactivated mode
    name_pr_a = types.Attribute(enums.Tag.Name, 0, types.Name(
        name_test + "private", enums.NameType.UninterpretedTextString))
    usage_pr_a = types.Attribute(
        "Cryptographic Usage Mask",
        0,
        enums.CryptographicUsageMask.Sign.value)
    att_pr_template = types.PrivateKeyTemplateAttribute(
        None, [name_pr_a, usage_pr_a])

    name_pu_a = types.Attribute(enums.Tag.Name, 0, types.Name(
        name_test + "_public", enums.NameType.UninterpretedTextString))
    usage_pu_a = types.Attribute(
        "Cryptographic Usage Mask",
        0,
        enums.CryptographicUsageMask.Verify.value)
    att_pu_template = types.PublicKeyTemplateAttribute(
        None, [name_pu_a, usage_pu_a])

    algo_a = types.Attribute(
        "Cryptographic Algorithm",
        0,
        enums.CryptographicAlgorithm.RSA)
    length_a = types.Attribute("Cryptographic Length", 0, 1024)
    crypt_param = types.CryptographicParameters()
    crypt_param.hashing_algorithm = enums.HashingAlgorithm.SHA_256
    crypt_param.CryptographicAlgorithm = enums.CryptographicAlgorithm.RSA
    crypt_param.padding_method = enums.PaddingMethod.PKCS5
    param_a = types.Attribute(
        enums.Tag.CryptographicParameters, 0, crypt_param)
    att_template = types.CommonTemplateAttribute(
        None, [algo_a, length_a, param_a])

    payload = types.CreateKeyPairRequestPayload(
        att_template, att_pr_template, att_pu_template)

    b = client.Batch(payload)
    r = clt.post_batch(b)

    # Verify asymm key created
    assert r
    assert isinstance(r[0], types.CreateKeyPairResponsePayload)
    assert r[0].private_key_unique_identifier
    assert r[0].public_key_unique_identifier
    u_id_pr = r[0].private_key_unique_identifier
    u_id_pl = r[0].public_key_unique_identifier

    # Locate public by private attribute
    r = locate_obj([types.Attribute("Object Type", 0, enums.ObjectType.PublicKey), types.Attribute(
        enums.Tag.Link, 0, types.Link(enums.LinkType.PrivateKeyLink, u_id_pr))], clt)
    assert r
    assert isinstance(r[0], types.LocateResponsePayload)
    assert r[0].unique_identifier_list[0]
    assert u_id_pl == r[0].unique_identifier_list[0]

    # Locate private by public
    r = locate_obj([types.Attribute("Object Type", 0, enums.ObjectType.PrivateKey), types.Attribute(
        enums.Tag.Link, 0, types.Link(enums.LinkType.PublicKeyLink, u_id_pl))], clt)
    assert r
    assert isinstance(r[0], types.LocateResponsePayload)
    assert r[0].unique_identifier_list[0]
    assert u_id_pr == r[0].unique_identifier_list[0]

    # Destroy public key
    r = destroy_obj(u_id_pl, clt)
    assert not isinstance(r[0], KmipError)
    assert r[0].unique_identifier == u_id_pl

    # Destroy private key
    r = destroy_obj(u_id_pr, clt)
    assert not isinstance(r[0], KmipError)
    assert r[0].unique_identifier == u_id_pr

# Params for hash (hashed data was collected by openssl on
# DONT_CHANGE.hash_test)
HASH_PARAMS = [
    # Not supported (enums.HashingAlgorithm.MD4,  ""),
    (enums.HashingAlgorithm.MD5, "05cca61a14394275c9e09c80edd273b8"),
    (enums.HashingAlgorithm.SHA_1, "f3b1c1072f179971dcc52c3b4b77cbc7e4504eea"),
    (enums.HashingAlgorithm.SHA_256,
     "37cc352f79d5ebaaa98332280719652b865843b81d5ddf7c175c1393c4ed5a27"),
    (enums.HashingAlgorithm.SHA_384,
     "1004c841b5316b765df2ba4b3436a577a64da60805c60faf937c765bfdb288ea85492236168c149619d3908b9e76f8bb"),
    (enums.HashingAlgorithm.SHA_512,
     "0b3c7ce69a0f27acc4f68e1fe97d3a35e9372383156d36b90f7d76cdd9e353c3df7fab9db83291e8925350cb778cb07774c80512f5b0819946afab4e828ed16b"),
    # Not supported (enums.HashingAlgorithm.RIPEMD_160,  ""),
    # Not supported (enums.HashingAlgorithm.Whirlpool, ""),
]


@server_test
@pytest.mark.parametrize("protocol", TESTED_PROTOCOLS)
@pytest.mark.parametrize("hash_algo, hashed_data", HASH_PARAMS)
def test_server_hash(
        host,
        httpsPort,
        cacert,
        cert,
        key,
        protocol,
        hash_algo,
        hashed_data):
    # Verify that there is data
    assert HASH_BYTES
    data = HASH_BYTES

    clt = client_instance(
        host,
        httpsPort,
        TTLV_PORT,
        protocol,
        cacert,
        cert,
        key)

    # Request to kmip server
    r = hash_data(hash_algo, data, clt)

    assert isinstance(r[0], types.HashResponsePayload)
    assert r[0].data

    # Verify if data's been corrected hashed
    h_data = binascii.b2a_hex(r[0].data)
    assert h_data.decode("ascii") == hashed_data


@server_test
@pytest.mark.parametrize("protocol", TESTED_PROTOCOLS)
def test_server_list_se_app(host, httpsPort, protocol, cacert, cert, key):
    clt = client_instance(
        host,
        httpsPort,
        TTLV_PORT,
        protocol,
        cacert,
        cert,
        key)

    # Test empty list
    r = list_se_app(None, clt)
    assert r
    assert isinstance(r[0], types.ListSEApplicationsResponsePayload)
    if r[0].located_items is not None:
        assert r[0].located_items == 0
    if r[0].application_basic_info_list is not None:
        assert len(r[0].application_basic_info_list) == 0

    # Register "1" SE app
    payload = types.RegisterSEApplicationRequestPayload()
    payload.file_type = enums.FileType.PythonScript
    app_1_name = "1_test_list_SEapp_" + str(protocol)
    payload.application_name = app_1_name
    payload.start_now = False
    assert BYTE_APP_DATA
    payload.file_data = BYTE_APP_DATA
    b = client.Batch(payload)
    r = clt.post_batch(b)

    # Verify the register SE app request
    assert r
    assert isinstance(r[0], types.RegisterSEApplicationResponsePayload)
    assert r[0].unique_identifier
    # it should not exist, cause It has not started on loading
    assert r[0].instance_identifier is None
    assert r[0].file_data_digest
    assert r[0].hashing_algorithm
    u_id_app_1 = r[0].unique_identifier

    # Register "2" SE app
    payload = types.RegisterSEApplicationRequestPayload()
    payload.file_type = enums.FileType.PythonScript
    app_2_name = "2_test_list_SEapp_" + str(protocol)
    payload.application_name = app_2_name
    payload.start_now = False
    payload.file_data = BYTE_APP_DATA
    b = client.Batch(payload)
    r = clt.post_batch(b)

    # Verify the register SE app request
    assert r
    assert isinstance(r[0], types.RegisterSEApplicationResponsePayload)
    assert r[0].unique_identifier
    # it should not exist, cause It has not started on loading
    assert r[0].instance_identifier is None
    assert r[0].file_data_digest
    assert r[0].hashing_algorithm
    u_id_app_2 = r[0].unique_identifier

    # Test list nothing, even it has added 2 SE app
    r = list_se_app(0, clt)
    assert r
    assert isinstance(r[0], types.ListSEApplicationsResponsePayload)
    if r[0].located_items is not None:
        assert r[0].located_items == 2
    if r[0].application_basic_info_list is not None:
        assert len(r[0].application_basic_info_list) == 0

    # List registered apps above
    r = list_se_app(None, clt)
    assert r
    assert isinstance(r[0], types.ListSEApplicationsResponsePayload)
    assert r[0].located_items == 2
    assert r[0].application_basic_info_list is not None
    assert len(r[0].application_basic_info_list) == 2

    # Verify if apps on list is correct
    if r[0].application_basic_info_list[0].application_name == app_2_name:
        assert r[0].application_basic_info_list[
            0].unique_identifier == u_id_app_2
        assert r[0].application_basic_info_list[
            0].application_instance_info_list is None
        assert r[0].application_basic_info_list[
            1].unique_identifier == u_id_app_1
        assert r[0].application_basic_info_list[
            1].application_instance_info_list is None

    else:
        assert r[0].application_basic_info_list[
            0].unique_identifier == u_id_app_1
        assert r[0].application_basic_info_list[
            0].application_instance_info_list is None
        assert r[0].application_basic_info_list[
            1].unique_identifier == u_id_app_2
        assert r[0].application_basic_info_list[
            1].application_instance_info_list is None

    # Delete "1" app registered
    r = delete_se_app(u_id_app_1, clt)
    assert r
    assert isinstance(r[0], types.DeleteSEApplicationResponsePayload)
    assert u_id_app_1 == r[0].unique_identifier

    # Delete "2" app registered
    r = delete_se_app(u_id_app_2, clt)
    assert r
    assert isinstance(r[0], types.DeleteSEApplicationResponsePayload)
    assert u_id_app_2 == r[0].unique_identifier


@server_test
@pytest.mark.parametrize("protocol", TESTED_PROTOCOLS)
def test_server_register_se_app(host, httpsPort, protocol, cacert, cert, key):
    clt = client_instance(
        host,
        httpsPort,
        TTLV_PORT,
        protocol,
        cacert,
        cert,
        key)

    # Register app
    payload = types.RegisterSEApplicationRequestPayload()
    payload.file_type = enums.FileType.PythonScript
    payload.application_name = "test_register_SEapp_" + str(protocol)
    payload.file_data = bytes()  # Fill bellow
    payload.start_now = False

    # Useless parameters
    payload.application_entry_point = ""
    payload.start_on_boot = False
    payload.non_stop = False
    payload.init_indicator = False

    # Get bytes from the file
    assert BYTE_APP_DATA
    payload.file_data = BYTE_APP_DATA

    # Post
    b = client.Batch(payload)
    r = clt.post_batch(b)

    # Verify register SE app request
    assert r
    assert isinstance(r[0], types.RegisterSEApplicationResponsePayload)
    assert r[0].unique_identifier
    # it should not exist, cause It has not started on boot
    assert r[0].instance_identifier is None
    assert r[0].file_data_digest
    assert r[0].hashing_algorithm
    u_id_app = r[0].unique_identifier

    # Verify the hashed data, according to used hashing algorithm
    digest = r[0].file_data_digest
    r = hash_data(r[0].hashing_algorithm, BYTE_APP_DATA, clt)
    assert isinstance(r[0], types.HashResponsePayload)
    assert r[0].data
    assert r[0].data == digest

    # Delete registered SE app
    r = delete_se_app(u_id_app, clt)
    assert r
    assert isinstance(r[0], types.DeleteSEApplicationResponsePayload)
    assert u_id_app == r[0].unique_identifier


@server_test_no_unix_socket
@pytest.mark.parametrize("protocol", TESTED_PROTOCOLS)
def test_server_flow_se_app(host, httpsPort, protocol, cacert, cert, key):
    clt = client_instance(
        host,
        httpsPort,
        TTLV_PORT,
        protocol,
        cacert,
        cert,
        key)

    # Register app
    payload = types.RegisterSEApplicationRequestPayload()
    payload.file_type = enums.FileType.PythonScript
    payload.application_name = "test_flow_SEapp_" + str(protocol)
    payload.start_now = True
    # Get bytes from the file
    assert BYTE_APP_DATA
    payload.file_data = BYTE_APP_DATA
    b = client.Batch(payload)
    r = clt.post_batch(b)

    # Verify register SE app request
    assert r
    assert isinstance(r[0], types.RegisterSEApplicationResponsePayload)
    assert r[0].unique_identifier
    # it should exist, cause It has started on boot
    assert r[0].instance_identifier
    assert r[0].file_data_digest
    assert r[0].hashing_algorithm
    u_id_app = r[0].unique_identifier
    iid_app = r[0].instance_identifier

    # Verify the hashed data, according to used hashing algorithm
    digest = r[0].file_data_digest
    r = hash_data(r[0].hashing_algorithm, BYTE_APP_DATA, clt)
    assert isinstance(r[0], types.HashResponsePayload)
    assert r[0].data
    assert r[0].data == digest

    # Waiting for finishing SE App execution
    running_app = True
    while running_app:
        time.sleep(3)

        r = list_se_app(None, clt)
        assert r
        assert isinstance(r[0], types.ListSEApplicationsResponsePayload)
        for binfo in r[0].application_basic_info_list:
            if binfo.unique_identifier != u_id_app or binfo.application_instance_info_list is None:
                continue
            else:
                for iinfo in binfo.application_instance_info_list:
                    running_app = iinfo.application_running
                    print(running_app)

    # Attempt to locate symm key that has been created by above registered SE
    # App
    name_a = types.Attribute(
        enums.Tag.Name,
        0,
        types.Name(
            "example_create_app.py",
            enums.NameType.UninterpretedTextString))
    r = locate_obj([name_a, types.Attribute(
        "Object Type", 0, enums.ObjectType.SymmetricKey)], clt)
    assert r
    assert isinstance(r[0], types.LocateResponsePayload)
    assert r[0].unique_identifier_list
    assert r[0].unique_identifier_list[0]
    u_id = r[0].unique_identifier_list[0]

    # Destroy symm key created by the loaded SE app
    r = destroy_obj(u_id, clt)
    assert not isinstance(r[0], KmipError)
    assert r[0].unique_identifier == u_id

    # Delete registered SE app
    r = delete_se_app(u_id_app, clt)
    assert r
    assert isinstance(r[0], types.DeleteSEApplicationResponsePayload)
    assert u_id_app == r[0].unique_identifier


###### Auxiliar functions for Requesting on Kmip server  #######

def delete_se_app(u_id, clt):
    payload = types.DeleteSEApplicationRequestPayload(u_id)
    b = client.Batch(payload)
    return clt.post_batch(b)


def hash_data(hash_algo, data, clt):
    crypt_param = types.CryptographicParameters()
    crypt_param.hashing_algorithm = hash_algo
    payload = types.HashRequestPayload()
    payload.cryptographic_parameters = crypt_param
    payload.data = data
    b = client.Batch(payload)
    return clt.post_batch(b)


def list_se_app(max_items, clt):
    payload = types.ListSEApplicationsRequestPayload(max_items, None)
    b = client.Batch(payload)
    return clt.post_batch(b)


def start_se_app(u_id, list_str_args, clt):
    payload = types.StartSEApplicationRequestPayload(u_id, list_str_args)
    b = client.Batch(payload)
    return clt.post_batch(b)


def modify_attribute(u_id, attr, clt):
    payload = types.ModifyAttributeRequestPayload(u_id, attr)
    b = client.Batch(payload)
    return clt.post_batch(b)


def locate_obj(attribute_list, clt):
    locate_payload = types.LocateRequestPayload()
    locate_payload.attribute_list = attribute_list
    b = client.Batch(locate_payload)
    return clt.post_batch(b)


def destroy_obj(u_id, clt):
    payload = types.DestroyRequestPayload(u_id)
    b = client.Batch(payload)
    return clt.post_batch(b)


def deactivate_obj(u_id, clt):
    rev_payload = types.RevokeRequestPayload()
    rev_payload.unique_identifier = u_id
    rev_payload.revocation_reason = types.RevocationReason(
        enums.RevocationReasonCode.CessationOfOperation, None)
    b = client.Batch(rev_payload)
    return clt.post_batch(b)


def activate_obj(u_id, clt):
    payload = types.ActivateRequestPayload()
    payload.unique_identifier = u_id
    b = client.Batch(payload)
    return clt.post_batch(b)


def get_attributes(u_id, list_name, clt):
    payload = types.GetAttributesRequestPayload(u_id, list_name)
    b = client.Batch(payload)
    return clt.post_batch(b)


def client_instance(host, httpsPort, ttlvPort, protocol, cacert, cert, key):
    port = 0
    if protocol.name.startswith('HTTPS'):
        port = httpsPort
    elif protocol.name.startswith('TTLV'):
        port = ttlvPort
    return client.Client(host, port, protocol, cacert, (cert, key))
