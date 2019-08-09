kkmip: Kryptus KMIP Client
==========================

The ``kkmip`` package is a KMIP client written in Python. KMIP (Key Management Interoperability
Protocol) is a protocol for managing and using cryptographic keys and objects on a server.

``kkmip`` supports KMIP up to version 1.4; however, not all operations and attributes are supported.


Installation
============

Extract the package, change to the root directory of the package and run:

::

    pip install .


Quick Start
===========

1. Create a :class:`~.client.Client`;
2. Create the payload of the request (any subclass of :class:`~.types.RequestPayload`);
3. Post the request and receive the answer, which will be a corresponding subclass of
   :class:`~.types.ResponsePayload`.

Example:

.. literalinclude:: ../test/client_test.py
    :language: python
    :pyobject: test_example


About Dates
===========

Any datetime object passed to this library must be aware, e.g., have a `tzinfo` attribute.
The default Python library does not have timezone values to use; you can use a 3rd party library
such as `pytz <http://pytz.sourceforge.net/>`_.


Table of Contents
=================

.. toctree::
   :maxdepth: 5

   self
   tutorial.rst
   modules.rst

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

