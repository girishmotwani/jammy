"""
This is the base conftest.py file for Jammy.

conftest.py files in subdirectories will override.

"""

import logging
import pytest

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(module)s: '
                           '%(message)s', datefmt="%H:%M:%S")
logger = logging.getLogger(__name__)

def pytest_addoption(parser):
    parser.addoption("--subscriptionIds", required=True,
	help='Subscription Ids', nargs=3)
    parser.addoption("--subscriptionId", action="store", default="f6cb8187-b300-4c2d-9b23-c00e7e98d799")
    parser.addoption("--location", action="store", default="eastus")
    parser.addoption("--policyLocation", action="store", default="eastus")
    parser.addoption("--resourceGroup", action="store", default="testRCG01")
    parser.addoption("--numrcg", action="store", default="1")
    parser.addoption("--numrc", action="store", default="1")
    parser.addoption("--numrules", action="store", default="1")



@pytest.fixture
def subscriptionId(request):
    return request.config.getoption("--subscriptionId")

@pytest.fixture
def subscriptionIds(request):
    return request.config.getoption("--subscriptionIds")

@pytest.fixture
def location(request):
    return request.config.getoption("--location")

@pytest.fixture
def policyLocation(request):
    return request.config.getoption("--policyLocation")

@pytest.fixture
def resourceGroup(request):
    return request.config.getoption("--resourceGroup")

@pytest.fixture
def num_rules(request):
    return request.config.getoption("--numrules")

@pytest.fixture
def num_rcg(request):
    return request.config.getoption("--numrcg")

@pytest.fixture
def num_rc(request):
    return request.config.getoption("--numrc")