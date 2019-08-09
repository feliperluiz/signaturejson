# content of conftest.py
import pytest

# TODO: XXX: Deafult Kryptus specific code, change if open-source
def pytest_addoption(parser):
    parser.addoption("--host", action="store", help="it is the AHX5 IP address or URL")

    parser.addoption("--httpsPort", action="store", help="it is the AHX5 HTTPS requests port number")

    parser.addoption("--cacert", action="store", help="it is the AHX5 HTTPS requests port number")
  
    parser.addoption("--cert", action="store",  help="it is the path to client's certificate")

    parser.addoption("--key", action="store", help="it is the path to client's private key")

    parser.addoption("--unixSocket", action="store_true", help="it is the path to client's private key")


@pytest.fixture
def host(request):
    return request.config.getoption("--host")

@pytest.fixture
def httpsPort(request):
    return request.config.getoption("--httpsPort")

@pytest.fixture
def cacert(request):
    return request.config.getoption("--cacert")

@pytest.fixture
def cert(request):
    return request.config.getoption("--cert")

@pytest.fixture
def key(request):
    return request.config.getoption("--key")

@pytest.fixture
def unixSocket(request):
    return request.config.getoption("--unixSocket")
