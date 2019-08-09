Using Message Authentication Codes (MACs)
=========================================

Generating a MAC (Authenticating)
---------------------------------

Assuming that an HMAC key was previously generated or registered, use the
``MAC`` KMIP operation with the :class:`.MACRequestPayload` which returns a
:class:`.MACResponsePayload`:

.. literalinclude:: ../../test/example_test.py
    :language: python
    :pyobject: test_hmac_authenticate
    :start-after: # Start of example
    :end-before: # End of example
    :dedent: 4


The above example generates a MAC for the string ``"hello world"`` with an HMAC key (whose unique
identifier is assumed to be stored in the ``uid`` variable) and prints the generated MAC
``mac_data`` as a hex string.

The ``unique_identifier`` field specifies the key to generate the MAC with.


Verifying a MAC
---------------

Assuming that a HMAC key was previously generated or registered, it is possible use the
``MACVerify`` KMIP operation with the :class:`.MACVerifyRequestPayload` which returns a
:class:`.MACVerifyResponsePayload`:

.. literalinclude:: ../../test/example_test.py
    :language: python
    :pyobject: test_hmac_verify
    :start-after: # Start of example
    :end-before: # End of example
    :dedent: 4


The fields are the same as with the ``MAC`` operation, with the addition of the ``mac_data``
field where the MAC to be verified, as a byte string, is specified. In the above example,
the unique identifier of the HMAC key is assumed to be stored in the ``uid`` variable and the
MAC to verify is assumed to be stored in the ``mac_data`` variable.

The ``validity_indicator`` field in the response payload indicates if the verification was
successful (when it is equal to :attr:`.ValidityIndicator.Valid`).

.. danger::
    It is common to verify a MAC received by generating the expected MAC and checking if they are
    equal. That, however, is a sensitive operation that must be implemented carefully. It is safer
    to use the ``MACVerify`` operation instead.
