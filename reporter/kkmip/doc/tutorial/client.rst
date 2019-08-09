Creating and using a Client
===========================

A KMIP server is a TLS server to which a KMIP client connects to. The first step in sending requests
to the server is to instantiate a :class:`~.client.Client`:

.. literalinclude:: ../../test/example_test.py
    :language: python
    :pyobject: test_client
    :start-after: test_client():
    :dedent: 4


A KMIP server usually listens to port 5696 using the :attr:`.Protocol.TTLV` protocol,
and another port for TTLV, XML and JSON over HTTPS. Use the ``protocol`` parameter to specify
the protocol with one item of the :class:`.Protocol` enumeration.

The ``verify`` parameter specifies the path to the root certificate used to verify the authenticity of
the server certificate. The KMIP server operator should provide you this.

The ``cert`` parameter is a tuple with the paths to the client certificate and the client key. These
should also be provided to you by the KMIP server operator when the client was registered.

The :class:`~.client.Client` instance is lazy; it won't connect to the server until needed. The
instance can be reused across different threads. For performance, reuse the same client instance.


Posting Requests
----------------

The KMIP protocol specifies a set of requests which can be sent to the server. Each request is
basically a structure with a set of fields, where each field can also be another structure.
In this library, each request is represented by a class that subclasses
:class:`.RequestPayload`, all of them with names ending with ``RequestPayload``.
The server response, in turn, is a subclass of :class:`.ResponsePayload` with name
ending with ``ResponsePayload``. Each field is represented by a class attribute; if the field
can have multiple instances, then the attribute is a list.

The simplest way to post a request is to use the :meth:`.Client.post` method. It returns the
response payload or raises a :class:`.KmipError` on a KMIP error:

.. literalinclude:: ../../test/example_test.py
    :language: python
    :pyobject: test_client_post
    :start-after: test_client_post(c):
    :dedent: 4


In the above example, the client is calling the KMIP ``Query`` function, which queries the server
for information about its settings and supported features. The :class:`.QueryRequestPayload` has a
single field, which is a list of items from the :class:`.QueryFunction` enum, specifying which
types of information the client is asking the server. In the example, we are asking which operations
the server supports, and information about the server itself.

The response is a :class:`.QueryResponsePayload` which has a set of fields, which are filled
according to which types of information we asked. In this case, we are interested in the
:attr:`.QueryResponsePayload.operation_list` attribute, which is a list of items of the enum
:class:`.Operation`.



Batch of Requests
-----------------


For improved perfomance it is possible to send a batch of requests which will be sent together in
a single request, using the :class:`.Batch` class:

.. literalinclude:: ../../test/example_test.py
    :language: python
    :pyobject: test_client_batch
    :start-after: test_client_batch(c):
    :dedent: 4


The :class:`.Batch` class accepts multiple ``RequestPayload``-subclass instances. Additional
requests can be added with the :meth:`.Batch.add` method. Finally, the batch can be posted with the
:meth:`.Client.post_batch` method, which returns a list of ``ResponsePayload``-subclasses
respectively for each request added to the batch. If there was an error, then a :class:`KmipError`
instance will be included in the list instead of the ``ResponsePayload``.

In the above example, two ``RequestPayloads`` are created, one for the ``Query`` function and other
for the ``Hash`` function. After posting the request, the list of functions queried and the hash
computed are printed.



Handling Errors
---------------

When the server returns a KMIP error, it is thrown (:meth:`.Client.post`) or returned
(:meth:`.Client.post_batch`) as a :class:`.KmipError` exception. The exception has three attributes
which are defined in the KMIP spec: the ``result_status``, which is one item of the
:class:`.ResultStatus` enumeration; the ``result_reason``, which is one item of the
:class:`.ResultReason` enumeration; and the ``result_message``, an arbitrary string returned by the
server with additional information. It is advised to use ``result_status`` and ``result_reason``
for any business logic and only use ``result_message`` for logging and debugging, since the messages
can change between KMIP servers or versions of the same server.

In this example, we do a ``Get`` operation using a object identifier that mostly likely does not
exist.

.. literalinclude:: ../../test/example_test.py
    :language: python
    :pyobject: test_client_error
    :start-after: test_client_error(c):
    :dedent: 4


The above prints ``ResultStatus.OperationFailed ResultReason.ItemNotFound`` along with the server
message.

.. warning::
    The ``kkmip`` library may also throw other exceptions on connection-related errors.

