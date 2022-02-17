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
    parser.addoption("--subscriptionId", action="store", default="f6cb8187-b300-4c2d-9b23-c00e7e98d799")
    parser.addoption("--location", action="store", default="eastus")
    parser.addoption("--resourceGroup", action="store", default="testRCG01")



@pytest.fixture
def subscriptionId(request):
    return request.config.getoption("--subscriptionId")


@pytest.fixture
def location(request):
    return request.config.getoption("--location")

@pytest.fixture
def location(request):
    return request.config.getoption("--policyLocation")

@pytest.fixture
def resourceGroup(request):
    return request.config.getoption("--resourceGroup")
