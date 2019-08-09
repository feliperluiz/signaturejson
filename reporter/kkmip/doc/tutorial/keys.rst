Generating and Registering Keys
===============================

Generating an RSA key pair
--------------------------

To generate an RSA key pair, use the ``CreateKeyPair`` KMIP request with the
:class:`.CreateKeyPairRequestPayload` which returns a :class:`.CreateKeyPairResponsePayload`:

.. literalinclude:: ../../test/example_test.py
    :language: python
    :pyobject: test_rsa_gen
    :start-after: test_rsa_gen(c):
    :end-before: # End of example
    :dedent: 4


.. note::
    The code can be very verbose due to the KMIP structure, but this approach is the most flexible.
    A higher-level API may be provided in the future.

The key parameters are specified in a set of KMIP Attributes. The payload has three fields:
``common_template_attribute`` holds the attributes that will be shared by the private and the public
keys that will be generated, while ``private_key_template_attribute`` has the attributes specific
to the private key and respectively for the ``public_key_template_attribute``.

The :class:`.CommonTemplateAttribute`, :class:`.PrivateKeyTemplateAttribute` and
:class:`.PublicKeyTemplateAttribute` structures can hold either templates (which are previously
registered sets of attributes) or actual list of attributes. Templates were deprecated in recent
KMIP versions, but the indirection in the structure unfortunately remains.

The ``attribute_list`` field of these structures finally hold the list of attributes.

Each attribute is represented by :class:`.Attribute` structure. This has two required fields:
``attribute_name`` and ``attribute_value``. Confusingly, KMIP uses a string to identify the kind of
attribute being specified, in ``attribute_name``. To prevent typos, ``kkmip`` supports passing the
tag of the desired attribute; this is the approach of the above example.

.. note::
    A "tag" is a numeric identifier for some type of data handled by KMIP. Each KMIP Attribute has
    a tag, but all other structures and fields have tags as well.

The ``attribute_value`` finally holds the value of the attribute. Its type depends on the attribute
specified. For example, the ``CryptographicLength`` attribute is an integer. Check the
:class:`.Attribute` documentation for a list of KMIP Attributes and their respective types.

The following attributes are commonly used when creating an RSA key pair:

* ``CryptographicAlgorithm``: with the value :attr:`.CryptographicAlgorithm.RSA`;
* ``CryptographicLength``: with the desired key length;
* ``Name``: with the name of the private (resp. public) key. Optional, but must be unique for all registered
  objects in the server (thus the private and public keys must have different names).
  Makes it easier to locate the key afterwards.
* ``CryptographicUsageMask``: specifies the allowed usages of the respective key; you can combine
  multiple uses by or-ing :class:`.CryptographicUsageMask` elements.

The :class:`.CreateKeyPairResponsePayload` returns the unique identifiers (strings) of the created
keys in the ``private_key_unique_identifier`` and ``public_key_unique_identifier`` fields.


Registering an existing RSA key
-------------------------------

To register an existing RSA key, use the ``Register`` KMIP request with the
:class:`.RegisterRequestPayload` which returns a :class:`.RegisterResponsePayload`:

.. literalinclude:: ../../test/example_test.py
    :language: python
    :pyobject: test_rsa_register
    :start-after: # Start of example
    :end-before: # End of example
    :dedent: 4


The above examples registers an RSA private key in PKCS#1 format. Note that KMIP only accepts key in
DER (binary) format instead of the more common PEM (ASCII) format; you may need to convert your
key.

The :class:`.RegisterRequestPayload` has three fields: ``object_type`` specifies the kind of object
being registered (private key, public key, certificate...) and is a :class:`.ObjectType` item.

The ``template_attribute`` specifies a set of KMIP Attributes of the object being registered,
similar to the ``CreateKeyPair`` operation.

The ``key_block`` specifies the key itself as a :class:`.KeyBlock` structure. Its main fields are
``key_format_type`` specifying the format of the key as a :class:`.KeyFormatType` enum;
``key_value`` specifying the key as a :class:`.KeyValue` structure;
``cryptographic_algorithm`` and ``cryptographic_length`` specifying the cryptographic algorithm
of the key (e.g. RSA) and its length. These two last fields can be derived by the server from the
``key_value``.

The :class:`.KeyValue` structure has two fields: the ``key_material`` which finally holds the
key itself (its format depends on the ``key_format_type`` of the :class:`.KeyBlock`; for PKCS#1,
it is a byte string), and ``attributes`` which is optional and can hold KMIP Attributes that will
be stored along with the key. This is useful for keeping attributes if the key is wrapped, since
these are included with the wrapped key.

.. caution::
    Beware of the redundancy of the KMIP spec in this regard. The ``CryptographicLength`` can be
    specified as an attribute in :attr:`.RegisterRequestPayload.template_attribute`, in
    :attr:`KeyBlock.cryptographic_length` and also as an attribute in
    :attr:`KeyMaterial.attributes`.


Generating an AES key
---------------------

To generate an AES key, use the ``Create`` KMIP request with the
:class:`.CreateRequestPayload` which returns a :class:`.CreateResponsePayload`:

.. literalinclude:: ../../test/example_test.py
    :language: python
    :pyobject: test_aes_gen
    :start-after: # Start of example
    :end-before: # End of example
    :dedent: 4


Its overall structure is similar to the RSA key pair generation. The :class:`.CreateRequestPayload`
has a ``object_type`` field with a :class:`.ObjectType` enum where we must specify the generation of
a symmetric key. The field ``template_attribute`` holds the attributes desired for the generated
key. We must specify at least ``CryptographicAlgorithm`` (AES in our example) and
``CryptographicLength`` (128 bits in our example). We also specify a name for the object.

Like the previous operations, the response contains an ``unique_identifier`` field with the
unique identifier of the generated key.


Generating an HMAC key
----------------------

To generate an HMAC key, use the ``Create`` KMIP request with the
:class:`.CreateRequestPayload` which returns a :class:`.CreateResponsePayload`:

.. literalinclude:: ../../test/example_test.py
    :language: python
    :pyobject: test_hmac_gen
    :start-after: # Start of example
    :end-before: # End of example
    :dedent: 4


The :class:`.CreateRequestPayload`
has a ``object_type`` field with a :class:`.ObjectType` enum where we must specify the generation of
a symmetric key. The field ``template_attribute`` holds the attributes desired for the generated
key. We must specify at least ``CryptographicAlgorithm`` (HMAC_SHA256 in our example) and
``CryptographicLength`` (256 bits in our example). We also specify a name for the object.

Like the previous operations, the response contains an ``unique_identifier`` field with the
unique identifier of the generated key.
