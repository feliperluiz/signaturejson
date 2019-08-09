from __future__ import (print_function, division, unicode_literals, absolute_import)

import pytest

host_option = pytest.config.getoption("--host")
httpsPort_option = pytest.config.getoption("--httpsPort")
cacert_option = pytest.config.getoption("--cacert", False)
cert_option = pytest.config.getoption("--cert")
key_option = pytest.config.getoption("--key")

# Skip server test, case it hasnt passed the kmip server arguments
server_test = pytest.mark.skipif(
    not (host_option and httpsPort_option and cert_option and key_option),
    reason="Must have kmip server parameters (host, httpsPort, cert and key) or "
           "unixSocket flag"
)


@pytest.fixture
def c(request, host, httpsPort, cacert, cert, key):
    from kkmip import client
    return client.Client(host=host, port=5696, protocol=client.Protocol.TTLV, verify=cacert,
                         cert=(cert, key), version=(1, 4))


@pytest.mark.skip
def test_client():
    from kkmip import client

    c = client.Client(host='example.com', port=5696, protocol=client.Protocol.TTLV,
                      verify='server.crt', cert=('client.crt', 'client.key'))


@server_test
def test_client_post(c):
    from kkmip import types
    from kkmip import enums

    payload = types.QueryRequestPayload([
        enums.QueryFunction.QueryOperations,
    ])
    r = c.post(payload)
    print(r.operation_list)


@server_test
def test_client_batch(c):
    import codecs
    from kkmip import types
    from kkmip import enums
    from kkmip import client

    query_payload = types.QueryRequestPayload([
        enums.QueryFunction.QueryOperations,
    ])

    hash_payload = types.HashRequestPayload(
        cryptographic_parameters=types.CryptographicParameters(
            hashing_algorithm=enums.HashingAlgorithm.SHA_256
        ),
        data='Hello world'.encode('utf-8')
    )

    batch = client.Batch(query_payload, hash_payload)

    responses = c.post_batch(batch)

    print(responses[0].operation_list)
    print(codecs.encode(responses[1].data, 'hex').decode('ascii'))


@server_test
def test_client_error(c):
    from kkmip.error import KmipError
    from kkmip import types

    payload = types.GetRequestPayload(
        unique_identifier='non existent identifier'
    )

    try:
        r = c.post(payload)
    except KmipError as e:
        print(e.result_status, e.result_reason, e.result_message)


@server_test
def test_rsa_gen(c):
    from kkmip import types
    from kkmip import enums

    payload = types.CreateKeyPairRequestPayload(
        common_template_attribute=types.CommonTemplateAttribute(
            attribute_list=[
                types.Attribute(
                    attribute_name=enums.Tag.CryptographicAlgorithm,
                    attribute_value=enums.CryptographicAlgorithm.RSA,
                ),
                types.Attribute(
                    attribute_name=enums.Tag.CryptographicLength,
                    attribute_value=2048,
                ),
            ],
        ),
        private_key_template_attribute=types.PrivateKeyTemplateAttribute(
            attribute_list=[
                types.Attribute(
                    attribute_name=enums.Tag.Name,
                    attribute_value=types.Name(
                        'my_private_key',
                        enums.NameType.UninterpretedTextString
                    )
                ),
                types.Attribute(
                    attribute_name=enums.Tag.CryptographicUsageMask,
                    attribute_value=enums.CryptographicUsageMask.Sign | enums.CryptographicUsageMask.Decrypt
                ),
            ],
        ),
        public_key_template_attribute=types.PublicKeyTemplateAttribute(
            attribute_list=[
                types.Attribute(
                    attribute_name=enums.Tag.Name,
                    attribute_value=types.Name(
                        'my_public_key',
                        enums.NameType.UninterpretedTextString
                    )
                ),
                types.Attribute(
                    attribute_name=enums.Tag.CryptographicUsageMask,
                    attribute_value=enums.CryptographicUsageMask.Verify | enums.CryptographicUsageMask.Encrypt
                ),
            ],
        ),
    )

    r = c.post(payload)
    print(r.private_key_unique_identifier, r.public_key_unique_identifier)
    # End of example
    c.post(types.DestroyRequestPayload(r.private_key_unique_identifier))
    c.post(types.DestroyRequestPayload(r.public_key_unique_identifier))


@server_test
def test_rsa_register(c, delete=True):
    # Start of example
    import codecs
    from kkmip import types
    from kkmip import enums

    pkcs1_rsa_key = """MIICXQIBAAKBgQC8ib0SkD1rG4MCpmhJBosRQ3ZbkxOTguqRO2diqRp4vdzlDrp6
    ERU1tTcvxbh2HhJGj8JRwMWHk2me7K9tQPLkZrSpPMI4/ks27w+Ohr7HjqCG3Yv6
    pL7GKMU+sT1I9ISy1gFUgN6J/2bFtBaENlWWz3hcLE+HXS7vuolCpzTUDwIDAQAB
    AoGALGmN3meX8Dkk3WTxv/IIpGJt6Rh2ThNSyi9iJT2MfNDMzjBwAP0xL9umSlyb
    HUfsKi8HKVbtsQgqo0NB98yK6pcrcYprphjbtsoAOO4AugqzoKIwzd7c4h5aPfDk
    VuxBBXUOzOdA2+htaMKIVDN7LL0yFfpyY5DagyjTPzocHRECQQDkB0bawy1YOfr3
    +Uq6zyfroCgjnKNUK7d8BExCocAM8DxbUpiSGYryqmS3pwm99vDy4G4hCa8CIEFw
    dLyxG2etAkEA06pawdK6hNbWL9C8WO0AuEx+mc60rfRQUiQjblZsEw9gdNdcnabt
    +01sKeLyTFZJZEpnazZ9VJ8/GTA3EplSKwJBAIilV692sLCjJiL9j+u8ghawRf15
    O2MQQ4cc6Doxxe269OBg8a7zgZGDzJFFlw/wcFmLZlOEAw0KGUzzl7OmUY0CQQC1
    tBRdN02vI86TFZnarPplPCWiW/R3MLiTCzrvSXlVk2m2Y/q5y8eYaApmmtBt/9TZ
    J5ZIT2qf7mT4do+Qg9YpAkBafPDqqkVhXUqWOACOhTbsD7VwCcm1mSy1VCYYMBSr
    GUm6om5BG245rXM0rdt3hY7D07fhoDKEE3kZgNTL9cYv
    """
    # Convert base64 to binary
    pkcs1_rsa_key = codecs.decode(pkcs1_rsa_key.encode('ascii'), 'base64')

    payload = types.RegisterRequestPayload(
        object_type=enums.ObjectType.PrivateKey,
        template_attribute=types.TemplateAttribute(
            attribute_list=[
                types.Attribute(
                    attribute_name=enums.Tag.Name,
                    attribute_value=types.Name(
                        'imported_private_key',
                        enums.NameType.UninterpretedTextString
                    ),
                ),
                types.Attribute(
                    attribute_name=enums.Tag.CryptographicUsageMask,
                    attribute_value=enums.CryptographicUsageMask.Sign |
                                    enums.CryptographicUsageMask.Decrypt
                ),
            ],
        ),
        object=types.PrivateKey(
            key_block=types.KeyBlock(
                key_format_type=enums.KeyFormatType.PKCS_1,
                key_value=types.KeyValue(
                    key_material=pkcs1_rsa_key,
                ),
                cryptographic_algorithm=enums.CryptographicAlgorithm.RSA,
                cryptographic_length=1024,
            )
        )
    )

    r = c.post(payload)
    print(r.unique_identifier)
    # End of example
    if delete:
        c.post(types.DestroyRequestPayload(r.unique_identifier))
    return r.unique_identifier


@server_test
def test_rsa_register_pubkey(c, delete=True):
    import codecs
    from kkmip import types
    from kkmip import enums

    pkcs1_rsa_key = """MIGJAoGBALyJvRKQPWsbgwKmaEkGixFDdluTE5OC6pE7Z2KpGni93OUOunoRFTW1
Ny/FuHYeEkaPwlHAxYeTaZ7sr21A8uRmtKk8wjj+SzbvD46GvseOoIbdi/qkvsYo
xT6xPUj0hLLWAVSA3on/ZsW0FoQ2VZbPeFwsT4ddLu+6iUKnNNQPAgMBAAE=
    """
    # Convert base64 to binary
    pkcs1_rsa_key = codecs.decode(pkcs1_rsa_key.encode('ascii'), 'base64')

    payload = types.RegisterRequestPayload(
        object_type=enums.ObjectType.PublicKey,
        template_attribute=types.TemplateAttribute(
            attribute_list=[
                types.Attribute(
                    attribute_name=enums.Tag.Name,
                    attribute_value=types.Name(
                        'imported_public_key',
                        enums.NameType.UninterpretedTextString
                    ),
                ),
                types.Attribute(
                    attribute_name=enums.Tag.CryptographicUsageMask,
                    attribute_value=enums.CryptographicUsageMask.Verify
                                    | enums.CryptographicUsageMask.Encrypt
                ),
            ],
        ),
        object=types.PublicKey(
            key_block=types.KeyBlock(
                key_format_type=enums.KeyFormatType.PKCS_1,
                key_value=types.KeyValue(
                    key_material=pkcs1_rsa_key,
                ),
                cryptographic_algorithm=enums.CryptographicAlgorithm.RSA,
                cryptographic_length=1024,
            )
        )
    )

    r = c.post(payload)
    print(r.unique_identifier)
    # End of example
    if delete:
        c.post(types.DestroyRequestPayload(r.unique_identifier))
    return r.unique_identifier


@server_test
def test_aes_gen(c, delete=True):
    # Start of example
    from kkmip import types
    from kkmip import enums

    payload = types.CreateRequestPayload(
        object_type=enums.ObjectType.SymmetricKey,
        template_attribute=types.TemplateAttribute(
            attribute_list=[
                types.Attribute(
                    attribute_name=enums.Tag.Name,
                    attribute_value=types.Name(
                        'my_aes_key',
                        enums.NameType.UninterpretedTextString
                    ),
                ),
                types.Attribute(
                    attribute_name=enums.Tag.CryptographicAlgorithm,
                    attribute_value=enums.CryptographicAlgorithm.AES,
                ),
                types.Attribute(
                    attribute_name=enums.Tag.CryptographicLength,
                    attribute_value=128,
                ),
                types.Attribute(
                    attribute_name=enums.Tag.CryptographicUsageMask,
                    attribute_value=enums.CryptographicUsageMask.Encrypt |
                                    enums.CryptographicUsageMask.Decrypt
                ),
            ],
        ),
    )

    r = c.post(payload)
    print(r.unique_identifier)
    # End of example

    if delete:
        c.post(types.DestroyRequestPayload(r.unique_identifier))
    return r.unique_identifier


def create_aes_key(c, name):
    from kkmip import types
    from kkmip import enums

    payload = types.CreateRequestPayload(
        object_type=enums.ObjectType.SymmetricKey,
        template_attribute=types.TemplateAttribute(
            attribute_list=[
                types.Attribute(
                    attribute_name=enums.Tag.Name,
                    attribute_value=types.Name(
                        name,
                        enums.NameType.UninterpretedTextString
                    ),
                ),
                types.Attribute(
                    attribute_name=enums.Tag.CryptographicAlgorithm,
                    attribute_value=enums.CryptographicAlgorithm.AES,
                ),
                types.Attribute(
                    attribute_name=enums.Tag.CryptographicLength,
                    attribute_value=128,
                ),
                types.Attribute(
                    attribute_name=enums.Tag.CryptographicUsageMask,
                    attribute_value=enums.CryptographicUsageMask.Encrypt |
                                    enums.CryptographicUsageMask.Decrypt
                ),
            ],
        ),
    )

    r = c.post(payload)
    return r.unique_identifier


@server_test
def test_locate(c):
    create_aes_key(c, 'my_aes_key')

    # Start of example
    from kkmip import types
    from kkmip import enums

    payload = types.LocateRequestPayload(
        attribute_list=[
            types.Attribute(
                attribute_name=enums.Tag.Name,
                attribute_value=types.Name(
                    'my_aes_key',
                    enums.NameType.UninterpretedTextString
                ),
            ),
        ],
    )

    r = c.post(payload)
    print(r.unique_identifier_list)
    # End of example
    c.post(types.DestroyRequestPayload(r.unique_identifier_list[0]))


@server_test
def test_locate_paging(c):
    uids = []
    for i in range(12):
        uids.append(create_aes_key(c, 'my_aes_key' + str(i)))

    # Start of example
    from kkmip import types
    from kkmip import enums

    offset_items = 0
    while True:
        payload = types.LocateRequestPayload(
            maximum_items=5,
            offset_items=offset_items,
            attribute_list=[
                types.Attribute(
                    attribute_name=enums.Tag.ObjectType,
                    attribute_value=enums.ObjectType.SymmetricKey,
                ),
            ],
        )
        r = c.post(payload)
        if not r.unique_identifier_list:
            break
        print(r.unique_identifier_list)
        offset_items += len(r.unique_identifier_list)
    # End of example

    for uid in uids:
        c.post(types.DestroyRequestPayload(uid))


@server_test
def test_destroy(c):
    uid = create_aes_key(c, 'my_aes_key')

    # Start of example
    from kkmip import types

    c.post(types.DestroyRequestPayload(uid))


@server_test
def test_activate(c, delete=True, uid=None):
    if uid is None:
        uid = test_rsa_register(c, delete=False)

    # Start of example
    from kkmip import types

    c.post(types.ActivateRequestPayload(uid))
    # End of example

    if delete:
        test_revoke(c, uid=uid)
    return uid


@server_test
def test_activation_date(c, delete=True):
    # Start of example
    import datetime
    import pytz
    from kkmip import types
    from kkmip import enums

    # Create a datetime 5 minutes in the past
    activation_date = datetime.datetime.now(pytz.UTC) - datetime.timedelta(minutes=5)

    payload = types.CreateRequestPayload(
        object_type=enums.ObjectType.SymmetricKey,
        template_attribute=types.TemplateAttribute(
            attribute_list=[
                types.Attribute(
                    attribute_name=enums.Tag.Name,
                    attribute_value=types.Name(
                        'my-aes-key',
                        enums.NameType.UninterpretedTextString
                    ),
                ),
                types.Attribute(
                    attribute_name=enums.Tag.CryptographicAlgorithm,
                    attribute_value=enums.CryptographicAlgorithm.AES,
                ),
                types.Attribute(
                    attribute_name=enums.Tag.CryptographicLength,
                    attribute_value=128,
                ),
                types.Attribute(
                    attribute_name=enums.Tag.ActivationDate,
                    attribute_value=activation_date,
                ),
            ],
        ),
    )

    r = c.post(payload)
    print(r.unique_identifier)
    # End of example

    if delete:
        test_revoke(c, uid=r.unique_identifier)


@server_test
def test_revoke(c, delete=True, uid=None):
    if uid is None:
        uid = test_activate(c, delete=False)

    # Start of example
    from kkmip import types
    from kkmip import enums

    payload = types.RevokeRequestPayload(
        unique_identifier=uid,
        revocation_reason=types.RevocationReason(
            revocation_reason_code=enums.RevocationReasonCode.CessationOfOperation
        ),
    )

    c.post(payload)
    # End of example

    if delete:
        c.post(types.DestroyRequestPayload(uid))
    return uid


@server_test
def test_sign(c, delete=True):
    uid = test_activate(c, delete=False)

    # Start of example
    import codecs
    from kkmip import types
    from kkmip import enums

    message = 'hello world'.encode('utf-8')

    payload = types.SignRequestPayload(
        unique_identifier=uid,
        cryptographic_parameters=types.CryptographicParameters(
            hashing_algorithm=enums.HashingAlgorithm.SHA_256,
            padding_method=enums.PaddingMethod.PSS,
        ),
        data=message,
    )

    r = c.post(payload)
    print(codecs.encode(r.signature_data, 'hex').decode('ascii'))
    # End of example
    if delete:
        test_revoke(c, uid=uid)
    return uid, r.signature_data


@server_test
def test_verify(c, delete=True):
    uid = test_rsa_register_pubkey(c, delete=False)
    test_activate(c, delete=False, uid=uid)
    priv_uid, signature_data = test_sign(c, delete=False)

    # Start of example
    from kkmip import types
    from kkmip import enums

    message = 'hello world'.encode('utf-8')

    payload = types.SignatureVerifyRequestPayload(
        unique_identifier=uid,
        cryptographic_parameters=types.CryptographicParameters(
            hashing_algorithm=enums.HashingAlgorithm.SHA_256,
            padding_method=enums.PaddingMethod.PSS,
        ),
        data=message,
        signature_data=signature_data,
    )

    r = c.post(payload)
    if r.validity_indicator == enums.ValidityIndicator.Valid:
        print('Signature is valid!')
    # End of example

    assert r.validity_indicator == enums.ValidityIndicator.Valid
    if delete:
        test_revoke(c, uid=uid)
        test_revoke(c, uid=priv_uid)


@server_test
def test_encrypt_aes(c, delete=True):
    uid = create_aes_key(c, 'my-aes-key')
    test_activate(c, delete=False, uid=uid)

    # Start of example
    import codecs
    from kkmip import types
    from kkmip import enums

    message = 'hello world'.encode('utf-8')

    payload = types.EncryptRequestPayload(
        unique_identifier=uid,
        cryptographic_parameters=types.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CTR,
            random_iv=True
        ),
        data=message,
    )

    r = c.post(payload)
    print(codecs.encode(r.data, 'hex').decode('ascii'))
    print(codecs.encode(r.iv_counter_nonce, 'hex').decode('ascii'))
    # End of example
    if delete:
        test_revoke(c, uid=uid)
    return uid, r.data, r.iv_counter_nonce


@server_test
def test_decrypt_aes(c):
    uid, encrypted_message, iv_counter_nonce = test_encrypt_aes(c, delete=False)

    # Start of example
    import codecs
    from kkmip import types
    from kkmip import enums

    payload = types.DecryptRequestPayload(
        unique_identifier=uid,
        cryptographic_parameters=types.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.CTR,
        ),
        data=encrypted_message,
        iv_counter_nonce=iv_counter_nonce,
    )

    r = c.post(payload)
    print(r.data.decode('utf-8'))
    # End of example

    test_revoke(c, uid=uid)


@server_test
def test_encrypt_aes_incremental(c, delete=True):
    uid = create_aes_key(c, 'my-aes-key')
    test_activate(c, delete=False, uid=uid)

    # Start of example
    import codecs
    from kkmip import types
    from kkmip import enums

    message = ('hello world' * 1000).encode('utf-8')
    encrypted_message = b''

    init_indicator = True
    final_indicator = False
    correlation_value = None
    block_size = 1000
    block_count = len(message) // block_size

    for i in range(block_count):
        if i == block_count - 1:
            final_indicator = True

        payload = types.EncryptRequestPayload(
            unique_identifier=uid,
            cryptographic_parameters=types.CryptographicParameters(
                block_cipher_mode=enums.BlockCipherMode.CTR,
                random_iv=True
            ),
            data=message[i * block_size:(i + 1) * block_size],
            init_indicator=init_indicator,
            final_indicator=final_indicator,
            correlation_value=correlation_value,
        )
        r = c.post(payload)
        encrypted_message += r.data
        correlation_value = r.correlation_value
        if init_indicator:
            print(codecs.encode(r.iv_counter_nonce, 'hex').decode('ascii'))
            init_indicator = False

    print(codecs.encode(encrypted_message, 'hex').decode('ascii'))
    # End of example

    if delete:
        test_revoke(c, uid=uid)

@server_test
def test_encrypt_aes_gcm(c, delete=True):
    uid = create_aes_key(c, 'my-aes-key')
    test_activate(c, delete=False, uid=uid)

    # Start of example
    import codecs
    from kkmip import types
    from kkmip import enums

    message = 'hello'.encode('utf-8')
    additional_data = 'data'.encode('utf-8')

    payload = types.EncryptRequestPayload(
        unique_identifier=uid,
        cryptographic_parameters=types.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.GCM,
            tag_length=12,
            random_iv=True,
        ),
        data=message,
        authenticated_encryption_additional_data=additional_data,
    )

    r = c.post(payload)
    print(codecs.encode(r.data, 'hex').decode('ascii'))
    print(codecs.encode(r.iv_counter_nonce, 'hex').decode('ascii'))
    print(codecs.encode(r.authenticated_encryption_tag, 'hex').decode('ascii'))
    # End of example
    if delete:
        test_revoke(c, uid=uid)
    return uid, r.data, r.iv_counter_nonce, r.authenticated_encryption_tag


@server_test
def test_decrypt_aes_gcm(c):
    uid, encrypted_message, iv_counter_nonce, tag = test_encrypt_aes_gcm(c, delete=False)

    # Start of example
    import codecs
    from kkmip import types
    from kkmip import enums

    additional_data = 'data'.encode('utf-8')

    payload = types.DecryptRequestPayload(
        unique_identifier=uid,
        cryptographic_parameters=types.CryptographicParameters(
            block_cipher_mode=enums.BlockCipherMode.GCM,
            tag_length=12,
        ),
        data=encrypted_message,
        authenticated_encryption_additional_data=additional_data,
        iv_counter_nonce=iv_counter_nonce,
        authenticated_encryption_tag=tag,
    )

    r = c.post(payload)
    print(r.data.decode('utf-8'))
    # End of example
    assert r.data.decode('utf-8') == 'hello'

    test_revoke(c, uid=uid)


@server_test
def test_encrypt_rsa(c, delete=True):
    uid = test_rsa_register_pubkey(c, delete=False)
    test_activate(c, delete=False, uid=uid)

    # Start of example
    import codecs
    from kkmip import types
    from kkmip import enums

    message = 'hello world'.encode('utf-8')

    payload = types.EncryptRequestPayload(
        unique_identifier=uid,
        cryptographic_parameters=types.CryptographicParameters(
            padding_method=enums.PaddingMethod.OAEP,
            hashing_algorithm=enums.HashingAlgorithm.SHA_256,
        ),
        data=message,
    )
    r = c.post(payload)

    print(codecs.encode(r.data, 'hex').decode('ascii'))
    # End of example

    if delete:
        test_revoke(c, uid=uid)
    return uid, r.data


@server_test
def test_decrypt_rsa(c, delete=True):
    uid = test_activate(c, delete=False)
    pubkey_uid, encrypted_message = test_encrypt_rsa(c, delete=False)

    # Start of example
    from kkmip import types
    from kkmip import enums

    payload = types.DecryptRequestPayload(
        unique_identifier=uid,
        cryptographic_parameters=types.CryptographicParameters(
            padding_method=enums.PaddingMethod.OAEP,
            hashing_algorithm=enums.HashingAlgorithm.SHA_256,
        ),
        data=encrypted_message,
    )
    r = c.post(payload)

    print(r.data.decode('utf-8'))
    # End of example

    if delete:
        test_revoke(c, uid=uid)
        test_revoke(c, uid=pubkey_uid)


@server_test
def test_hmac_gen(c, delete=True):
    # Start of example
    from kkmip import types
    from kkmip import enums

    payload = types.CreateRequestPayload(
        object_type=enums.ObjectType.SymmetricKey,
        template_attribute=types.TemplateAttribute(
            attribute_list=[
                types.Attribute(
                    attribute_name=enums.Tag.Name,
                    attribute_value=types.Name(
                        'my_hmac_key',
                        enums.NameType.UninterpretedTextString
                    ),
                ),
                types.Attribute(
                    attribute_name=enums.Tag.CryptographicAlgorithm,
                    attribute_value=enums.CryptographicAlgorithm.HMAC_SHA256,
                ),
                types.Attribute(
                    attribute_name=enums.Tag.CryptographicLength,
                    attribute_value=256,
                ),
                types.Attribute(
                    attribute_name=enums.Tag.CryptographicUsageMask,
                    attribute_value=enums.CryptographicUsageMask.MACGenerate |
                                    enums.CryptographicUsageMask.MACVerify
                ),
            ],
        ),
    )

    r = c.post(payload)
    print(r.unique_identifier)
    # End of example

    if delete:
        c.post(types.DestroyRequestPayload(r.unique_identifier))
    return r.unique_identifier


@server_test
def test_hmac_authenticate(c, delete=True):
    uid = test_hmac_gen(c, delete=False)
    test_activate(c, delete=False, uid=uid)

    # Start of example
    import codecs
    from kkmip import types
    from kkmip import enums

    message = 'hello world'.encode('utf-8')

    payload = types.MACRequestPayload(
        unique_identifier=uid,
        cryptographic_parameters=types.CryptographicParameters(
            cryptographic_algorithm=enums.CryptographicAlgorithm.HMAC_SHA256,
        ),
        data=message,
    )

    r = c.post(payload)
    print(codecs.encode(r.mac_data, 'hex').decode('ascii'))
    # End of example

    if delete:
        test_revoke(c, uid=uid)
    return uid, r.mac_data


@server_test
def test_hmac_verify(c, delete=True):
    uid, mac_data = test_hmac_authenticate(c, delete=False)

    # Start of example
    from kkmip import types
    from kkmip import enums

    message = 'hello world'.encode('utf-8')

    payload = types.MACVerifyRequestPayload(
        unique_identifier=uid,
        cryptographic_parameters=types.CryptographicParameters(
            cryptographic_algorithm=enums.CryptographicAlgorithm.HMAC_SHA256,
        ),
        data=message,
        mac_data=mac_data,
    )

    r = c.post(payload)
    if r.validity_indicator == enums.ValidityIndicator.Valid:
        print('MAC is valid!')
    # End of example

    assert r.validity_indicator == enums.ValidityIndicator.Valid
    if delete:
        test_revoke(c, uid=uid)
