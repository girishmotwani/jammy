"""
Tests for virtual WAN in Jammy
"""

import json
import os
import pytest
from jammy.armclient import ArmClient
from jammy.models.virtualWan import *
from jammy.models.virtualWan import version


class TestVirtualWan:

    cl = None

    @pytest.fixture
    def setup_rg(self, subscriptionId, resourceGroup, location):  
        self.cl = ArmClient()
        self.rg = self.cl.create_resource_group(subscriptionId, resourceGroup, location)


    def test_vwan_create_delete(self, setup_rg, subscriptionId, location, resourceGroup):
        vwan = VirtualWAN()
        vwan.location = location
        vwan.resourceGroup = resourceGroup

        resource_id = '/subscriptions/' + subscriptionId + '/resourceGroups/' + resourceGroup + '/providers/Microsoft.Network/virtualWans/jammyvwan01'
        resourceJson = json.dumps(vwan.serialize())
        resp = self.cl.put_resource(resource_id, resourceJson, version.VERSION)


