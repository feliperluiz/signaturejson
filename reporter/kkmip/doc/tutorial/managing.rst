Managing Keys
=============

Listing Keys
------------

In order to list keys (or other KMIP objects), use the ``Locate`` KMIP operation with the
:class:`.LocateRequestPayload` which returns a :class:`.LocateResponsePayload`:

.. literalinclude:: ../../test/example_test.py
    :language: python
    :pyobject: test_locate
    :start-after: # Start of example
    :end-before: # End of example
    :dedent: 4


The main argument to ``Locate`` is a list of attributes. It will return all objects that match the
given attributes. In our example, we find the object with name ``my_aes_key`` we created
before. ``Locate`` returns a list of unique identifiers of the objects that match the given
criteria.

If the result list is expected to be large, you can use "paging" in order to return the objects
in batches by using the ``maximum_items`` and ``offset`` fields.

.. literalinclude:: ../../test/example_test.py
    :language: python
    :pyobject: test_locate_paging
    :start-after: # Start of example
    :end-before: # End of example
    :dedent: 4


The ``maximum_items`` field specifies the maximum number of items to return, and ``offset``
specifies from which index (in the total list of matching objects) the server should return. In the
above example, the server returns the first five results; then the next five, and so on.

.. caution::
    If there is no matching elements or if ``offset`` it out of bounds then the server can return
    either an empty list or no list at all. In ``kkmip`` this is represented either as an empty list
    or as ``None``. This is why in the example above we use ``if not r.unique_identifier_list:``
    instead of ``if len(r.unique_identifier_list) == 0:``, since the former handles both cases.


Activating Keys
---------------

Before using a key for cryptographic purporses (e.g. encrypting, signing) it is required to first
activate it. This can be done with the ``Activate`` KMIP operation with the
:class:`.ActivateRequestPayload` which returns a :class:`.ActivateResponsePayload`:

.. literalinclude:: ../../test/example_test.py
    :language: python
    :pyobject: test_activate
    :start-after: # Start of example
    :end-before: # End of example
    :dedent: 4


Alternatively, you can set the ``ActivationDate`` KMIP Attribute to some date in the past when
creating or registering the object. This will also activate the object:

.. literalinclude:: ../../test/example_test.py
    :language: python
    :pyobject: test_activation_date
    :start-after: # Start of example
    :end-before: # End of example
    :dedent: 4


.. important::
    The ``kkmip`` library will only accept ``datetime`` objects that are
    `aware <https://docs.python.org/3/library/datetime.html>`_, i.e. that have timezone information
    (``tzinfo`` attribute). However, Python 2 and Python < 3.2 do not have any builtin support for
    timezones. Use Python 3.2+ ``timezone`` objects or third-party libraries like ``pytz``,
    which is used in the above example.


Revoking Keys
-------------

A key must be revoked if it will no longer be used or if it was compromised. It is not possible to
delete a key unless it is revoked first. Revoke a key with the ``Revoke`` KMIP operation with the
:class:`.RevokeRequestPayload` which returns a :class:`.RevokeResponsePayload`:

.. literalinclude:: ../../test/example_test.py
    :language: python
    :pyobject: test_revoke
    :start-after: # Start of example
    :end-before: # End of example
    :dedent: 4


The key to be revoked must be specified in the ``unique_identifier`` field along with the reason
for revocation in the ``revocation_reason`` field. The :class:`.RevocationReason` structure
holds the ``revocation_reason_code`` field with the corresponding code of the reason (the most
common being :attr:`.RevocationReason.CessationOfOperation` and
:attr:`.RevocationReason.KeyCompromise`) and the ``revocation_messsage`` with an arbitrary text
message with additional information about the revocation.


Deleting Keys
-------------

Delete keys (or any KMIP object) with the ``Destroy`` KMIP operation with the
:class:`.DestroyRequestPayload` which returns a :class:`.DestroyResponsePayload`:

.. literalinclude:: ../../test/example_test.py
    :language: python
    :pyobject: test_destroy
    :start-after: # Start of example
    :dedent: 4


Simply specify the unique identifier of the object that will be destroyed. You may need to use
``Locate`` in order to find the unique identifier of an object given its name, for example.

.. attention::
    A key must be revoked before it is deleted.
