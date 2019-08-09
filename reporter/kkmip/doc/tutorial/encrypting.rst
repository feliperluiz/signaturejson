Encrypting and Decrypting
=========================

Encrypting with AES
-------------------

Assuming that an AES key was previously generated or registered, use the
``Encrypt`` KMIP operation with the :class:`.EncryptRequestPayload` which returns a
:class:`.EncryptResponsePayload`:

.. literalinclude:: ../../test/example_test.py
    :language: python
    :pyobject: test_encrypt_aes
    :start-after: # Start of example
    :end-before: # End of example
    :dedent: 4


The ``unique_identifier`` specifies the key to encrypt with (the example assumes it is stored in the
``uid`` variable); ``cryptographic_parameters`` the encryption parameters while ``data`` is the data
to be encrypted.

The relevant fields of :class:`.CryptographicParameters` are: ``block_cipher_mode``, which specifies
the block cipher mode to use (e.g. CBC, CTR); and ``random_iv``, a boolean flag that specifies
if a random IV should be generated and used. If not specified or false then the IV must be
passed in the ``iv_counter_nonce`` field of  :class:`.EncryptRequestPayload`.

The response payload includes the ``data`` field with the encrypted data and the
``iv_counter_nonce`` with the randomly generated IV, which is required for decryption.

.. danger::
    Take care when specifying an IV in the ``iv_counter_nonce``. Security is lost if an IV is
    repeated or used incorrectly (e.g. in CBC mode the IV *must* be randomly generated).

.. danger::
    Encryption, by itself, does not fully protect data; a Message Authentication Code (MAC) must
    also be used.


Decrypting with AES
-------------------

Assuming that an AES key was previously generated or registered, use the
``Decrypt`` KMIP operation with the :class:`.DecryptRequestPayload` which returns a
:class:`.DecryptResponsePayload`:

.. literalinclude:: ../../test/example_test.py
    :language: python
    :pyobject: test_decrypt_aes
    :start-after: # Start of example
    :end-before: # End of example
    :dedent: 4


The above example is very similar to the ``Encrypt`` operation, with the difference that the
``data`` field now holds the encrypted data and ``iv_counter_nonce`` must be specified with the IV
used in the encryption process. The example assumes that the ``uid`` variable holds the unique
identifier of the key, while ``encrypted_message`` holds the encrypted data and ``iv_counter_nonce``
holds the IV used.

The response payload returns the decrypted message in the ``data`` field.


Incremental Encryption
----------------------

In some cases the data to be encrypted is too big to fit into a request. In this cases, KMIP
supports incremental encryption:

.. literalinclude:: ../../test/example_test.py
    :language: python
    :pyobject: test_encrypt_aes_incremental
    :start-after: # Start of example
    :end-before: # End of example
    :dedent: 4


Start an incremental encryption process by calling ``Encrypt``
with the ``init_indicator`` flag set to true. Save both the partial ciphertext (``data``) and the
``correlation_value``. The ``correlation_value`` identifies this encryption process and must be
provided in the next partial encryption call. In the final piece of data to be encrypted,
set the ``final_indicator`` to true.

The incremental decryption process is similar.


Encrypting with RSA
-------------------

Assuming that an RSA public key was previously generated or registered, also use the
``Encrypt`` KMIP operation with the :class:`.EncryptRequestPayload` which returns a
:class:`.EncryptResponsePayload`:

.. literalinclude:: ../../test/example_test.py
    :language: python
    :pyobject: test_encrypt_rsa
    :start-after: # Start of example
    :end-before: # End of example
    :dedent: 4


The ``unique_identifier`` specifies the public key to encrypt with (the example assumes it is stored
in the ``uid`` variable); ``cryptographic_parameters`` the encryption parameters while ``data`` is
the data to be encrypted.

The :class:`.CryptographicParameters` the relevant fields are ``padding_mode`` which specifies the
padding mode to use (e.g. PKCS#1 v1.5 or OAEP; the latter is preferred) and ``hashing_algorithm``
which is used by the padding mode.

The response payload includes the ``data`` field with the encrypted data.


Decrypting with RSA
-------------------

Assuming that an RSA private key was previously generated or registered, also use the
``Decrypt`` KMIP operation with the :class:`.DecryptRequestPayload` which returns a
:class:`.DecryptResponsePayload`:

.. literalinclude:: ../../test/example_test.py
    :language: python
    :pyobject: test_decrypt_rsa
    :start-after: # Start of example
    :end-before: # End of example
    :dedent: 4


The above example is very similar to the ``Decrypt`` operation, with the difference that the
``data`` field now holds the encrypted data. The example assumes that the ``uid`` variable holds the
unique identifier of the private key, while ``encrypted_message`` holds the encrypted data.

The response payload returns the decrypted message in the ``data`` field.
