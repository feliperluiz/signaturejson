Kryptus KMIP Client Python
==========================

This project contains a KMIP Client written in Python. This Client will be a python package that can
be imported in client applications.

For a client-oriented documentation, generate the Sphinx documentation as described below.


Generating documentation
========================

Install sphinx and additional libraries:
::

    pip install sphinx sphinx_rtd_theme

Run:
::

    sphinx-build -Ea doc/ doc/build/


The documentation will be generated in `doc/build`.


Testing
=======

In order to test the library, install tox, Python 2.7 and Python 3.5. For testing without a live KMIP server, run:
::

    tox

It will skip the tests that require a KMIP server. For all tests (including a live KMIP server), run:
::

    tox -- --unixSocket --host=HOST --httpsPort=PORT --cacert=CA_CERTIFICATE --cert=CLIENT_CERTIFICATE --key=CLIENT_PRIVATE_KEY

However, if using unix socket protocol is not feasible,  only test the KMIP server with HTTPS and TTLV protocols:
::

   tox -- --host=HOST --httpsPort=PORT --cacert=CA_CERTIFICATE --cert=CLIENT_CERTIFICATE --key=CLIENT_PRIVATE_KEY

It is also possible to test the KMIP Server only with unix socket protocol, by running:
::

    tox -- --unixSocket

Where:

* CLIENT_CERTIFICATE is the path to client's certificate
* CLIENT_PRIVATE_KEY is the path to client's private key
* HOST is the KMIP server IP address or URL
* PORT is the KMIP server HTTPS requests port number
* CA_CERTIFICATE is the path to the trusted CA's certificate


To sidestep `tox` and test with a specific Python version, install the package and call py.test:
::

    pip install -e . pytest

Testing without a live KMIP server:
::

    pytest

For the complete test (with a live KMIP server) with pytest, run on kmip-client directory:
::

   pytest --unixSocket --host=HOST --httpsPort=PORT --cacert=CA_CERTIFICATE --cert=CLIENT_CERTIFICATE --key=CLIENT_PRIVATE_KEY

Where the arguments are the same as above.

It is recommended to reset the database before running the tests with KMIP server.


Code Base
=========

Code documentation follows Google style.

This library is compatible with both Python 2 and Python 3. Code should be written following Python
3 practices when possible. It uses the `eight` compatibility library to achieve this. Code should
use these imports:

.. code-block:: python

    from __future__ import (print_function, division, unicode_literals, absolute_import)

