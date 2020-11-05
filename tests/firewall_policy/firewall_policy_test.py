"""
Tests for firewall policy in Jammy
"""

import json
import pytest
from jammy.armclient import ArmClient
from jammy.models.firewallPolicy import *
from jammy.models.firewallPolicy import version

class TestFirewallPolicy:
    def test_create_policy(self, subscriptionId, location, resourceGroup):
        #setup_test_env(sandbox_firewall_in_hub)
        # create resource group
        cl = ArmClient()
        cl.create_resource_group(subscriptionId, resourceGroup, location)

        fp = FirewallPolicy()
        fp.location = location
        fp.threat_intel_mode = 'Alert'

        resourceId = '/subscriptions/' + subscriptionId + '/resourceGroups/' + resourceGroup + '/providers/Microsoft.Network/firewallPolicies/fp02' 
        resourceJson = json.dumps(fp.serialize())
        resp = cl.put_resource(resourceId, resourceJson, version.VERSION)
        print(resp)

        resp = cl.get_resource(resourceId, version.VERSION)
        result_fp = FirewallPolicy.deserialize(json.loads(resp))

        assert result_fp
        cl.delete_resource(resourceId, version.VERSION)

    def test_create_policy_ti_deny(self, subscriptionId, location, resourceGroup):
        #setup_test_env(sandbox_firewall_in_hub)
        fp = FirewallPolicy()
        fp.location = location
        fp.threat_intel_mode = 'Deny'
        cl = ArmClient()
        resourceId = '/subscriptions/' + subscriptionId + '/resourceGroups/' + resourceGroup + '/providers/Microsoft.Network/firewallPolicies/testfp02'
        resourceJson = json.dumps(fp.serialize())
        resp = cl.put_resource(resourceId, resourceJson, version.VERSION)
        print(resp)

        resp = cl.get_resource(resourceId, version.VERSION)
        result_fp = FirewallPolicy.deserialize(json.loads(resp))

        assert result_fp

        cl.delete_resource(resourceId, version.VERSION)


    def test_policy_with_ruleCollectionGroup(self, subscriptionId, location, resourceGroup):
        fp = FirewallPolicy()
        fp.location = location
        fp.resourceGroup = resourceGroup

        cl = ArmClient()
        resourceId = '/subscriptions/' + subscriptionId + '/resourceGroups/' + resourceGroup + '/providers/Microsoft.Network/firewallPolicies/testfp02'
        resourceJson = json.dumps(fp.serialize())
        resp = cl.put_resource(resourceId, resourceJson, version.VERSION)

        print(resp)

        resourceId = resourceId + '/ruleCollectionGroups/rcg01'

        rcg = FirewallPolicyRuleCollectionGroup()
        rcg.priority = 200
        rcg.rule_collections = []
        rc = FirewallPolicyRuleCollection()
        rc.rule_collection_type = 'FirewallPolicyFilterRuleCollection'
        rcg.rule_collections.append(rc)

        resourceJson = json.dumps(rcg.serialize())

        resp = cl.put_resource(resourceId, resourceJson, version.VERSION)

        print(resp)
