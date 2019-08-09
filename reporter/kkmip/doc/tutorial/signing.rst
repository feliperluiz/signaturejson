Signing and Verifying Signatures
================================

Signing with RSA
----------------

Assuming that an RSA private key was previously generated or registered, it is possible to use the
``Sign`` KMIP operation with the :class:`.SignRequestPayload` which returns a
:class:`.SignResponsePayload`:

.. literalinclude:: ../../test/example_test.py
    :language: python
    :pyobject: test_sign
    :start-after: # Start of example
    :end-before: # End of example
    :dedent: 4


The above examples signs the string ``"hello world"`` with an existing RSA private key (whose unique
identifier is assumed to be stored in the ``uid`` variable) and prints the generated signature as a
hex string.

The ``unique_identifier`` field specifies the private key to sign with. The
``cryptographic_parameters`` field specifies the signature parameters to be used, while ``data``
holds the data to be signed.

.. attention::
    You can only sign binary data. If you want to sign text, you will need to convert it to a
    specific encoding such as UTF-8, like in the above example. Python 2 uses the ``str`` type
    for both string and binary data, which can result in confusion.

The :class:`.CryptographicParameters` structure is generic and can hold parameters for multiple
types of cryptographic operations. For signing, the relevant fields are ``hashing_algorithm`` (the
hashing algorithm used in the signature generation) and ``padding_method`` (the padding used in the
signature generation). The above example uses ``SHA-256`` and ``PSS`` padding, which is preferable
over the old ``PKCS1V1_5`` padding. The ``digital_signature`` field can specify both the hashing and
padding, but is less flexible.

.. tip::
    If a :class:`.CryptographicParameters` attribute is specified when generating or registering a
    key then it will be used as a source of default values for the parameters.

.. Commented because still not supported
    .. tip::
        In some cases it is more efficient to directly pass the hash of the message to be signed instead
        of passing the message and relying on the KMIP server to hash it. KMIP version 1.4 supports this
        with the :attr:`.SignRequestPayload.digested_data` attribute.


Verifying with RSA
------------------

Assuming that an RSA public key was previously generated or registered, it is possible to use the
``SignatureVerify`` KMIP operation with the :class:`.SignatureVerifyRequestPayload` which returns a
:class:`.SignatureVerifyResponsePayload`:

.. literalinclude:: ../../test/example_test.py
    :language: python
    :pyobject: test_verify
    :start-after: # Start of example
    :end-before: # End of example
    :dedent: 4


The fields are the same as with the ``Sign`` operation, with the addition of the ``signature_data``
field where the signature to be verified, as a byte string, is specified. In the above example,
the unique identifier of the public key is assumed to be stored in the ``uid`` variable and the
RSA signature to verify is assumed to be stored in the ``signature_data`` variable.

In the response payload, the ``validity_indicator`` field indicates whether the verification was
successful (when it is equal to :attr:`.ValidityIndicator.Valid`).
