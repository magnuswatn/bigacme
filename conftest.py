import pytest


def pytest_addoption(parser):
    parser.addoption("--lb", action="store", default='localhost',
                     help="BIG-IP hostname or IP address")
    parser.addoption("--user", action="store", help="BIG-IP username",
                     default="admin")
    parser.addoption("--pass", action="store", help="BIG-IP password",
                     default="admin")
    parser.addoption("--ca", action="store", help="ACME CA directory",
                     default="localhost")
    parser.addoption("--hostname", action="store", help="Hostname to retrive certificate for",
                     default="bigacme.no")
    parser.addoption("--datagroup", action="store", help="Datagroup for ACME challenges",
                     default="acme_responses_dg")
    parser.addoption("--partition", action="store", help="Partition where datagroup is located",
                     default="Common")

@pytest.fixture(scope="module")
def opt_lb(request):
    return request.config.getoption("--lb")

@pytest.fixture(scope="module")
def opt_username(request):
    return request.config.getoption("--user")

@pytest.fixture(scope="module")
def opt_password(request):
    return request.config.getoption("--pass")

@pytest.fixture(scope="module")
def opt_ca(request):
    return request.config.getoption("--ca")

@pytest.fixture(scope="module")
def opt_hostname(request):
    return request.config.getoption("--hostname")

@pytest.fixture(scope="module")
def opt_datagroup(request):
    return request.config.getoption("--datagroup")

@pytest.fixture(scope="module")
def opt_partition(request):
    return request.config.getoption("--partition")

