"""
Tests for firewall policy in Jammy
"""

import json
import os
import pytest
from jammy.armclient import ArmClient
from jammy.models.firewallPolicy import *
from jammy.models.firewallPolicy import version

from jammy.models.azurefirewall import AzureFirewall



class TestFirewallPolicy:

    cl = None

    @pytest.fixture
    def setup_rg(self, subscriptionId, resourceGroup, location):  
        self.cl = ArmClient()
        self.rg = self.cl.create_resource_group(subscriptionId, resourceGroup, location)

    def test_policy_with_ruleCollectionGroup(self, setup_rg, subscriptionId, location, resourceGroup):
        fp = FirewallPolicy()
        fp.location = location
        fp.resourceGroup = resourceGroup

        resourceId = '/subscriptions/' + subscriptionId + '/resourceGroups/' + resourceGroup + '/providers/Microsoft.Network/firewallPolicies/jammyFP01'
        resourceJson = json.dumps(fp.serialize())
        resp = self.cl.put_resource(resourceId, resourceJson, version.VERSION)

        print(resp)

        resourceId = resourceId + '/ruleCollectionGroups/rcg01'

        rcg = FirewallPolicyRuleCollectionGroup()
        rcg.priority = 200
        rcg.rule_collections = []
        rc = FirewallPolicyRuleCollection()
        rc.rule_collection_type = 'FirewallPolicyFilterRuleCollection'
        rcg.rule_collections.append(rc)

        resourceJson = json.dumps(rcg.serialize())

        resp = self.cl.put_resource(resourceId, resourceJson, version.VERSION)

        print(resp)

    def test_create_delete_vnet_fw(self, setup_rg, subscriptionId, location, resourceGroup):
        fp = FirewallPolicy()
        fp.location = location
        fp.resourceGroup = resourceGroup
        
        # first deploy the ARM template 
        template_file = os.path.join(os.path.dirname(__file__), 'templates', 'firewallPolicySandbox.json')
        self.cl.deploy_template(subscriptionId, "test-deployment", resourceGroup, location, template_file)
        
        # create firewall policy 
        resourceId = '/subscriptions/' + subscriptionId + '/resourceGroups/' + resourceGroup + '/providers/Microsoft.Network/firewallPolicies/jammyFP02'
        resourceJson = json.dumps(fp.serialize())
        resp = self.cl.put_resource(resourceId, resourceJson, version.VERSION)

        # create a rule collection group
        rcg_id = resourceId + '/ruleCollectionGroups/rcg01'

        net_rule = NetworkRule()
        net_rule.name = 'google_dns'
        net_rule.source_addresses = ['10.1.0.0/24']
        net_rule.destination_addresses = ['8.8.8.8', '8.8.8.4']
        net_rule.destination_ports = ["53"]
        net_rule.ip_protocols = [FirewallPolicyRuleNetworkProtocol.udp]

        
        rcg = FirewallPolicyRuleCollectionGroup()
        rcg.priority = 200
        rcg.rule_collections = []
        
        rc = FirewallPolicyFilterRuleCollection()
        allow_action = FirewallPolicyFilterRuleCollectionAction()
        allow_action.type = "ALLOW"
        rc.rule_collection_type = 'FirewallPolicyFilterRuleCollection'
        rc.name = "testRuleCollection01"
        rc.priority = 1000
        rc.action = allow_action
        rc.rules = [net_rule]
        rcg.rule_collections.append(rc)

        resourceJson = json.dumps(rcg.serialize())
        resp = self.cl.put_resource(rcg_id, resourceJson, version.VERSION)

        # now associate the firewall policy with the firewall deployed.
        fw_resourceId = '/subscriptions/' + subscriptionId + '/resourceGroups/' + resourceGroup + '/providers/Microsoft.Network/azureFirewalls/' + 'firewall1' 
        resp = self.cl.get_resource(fw_resourceId , "2020-07-01")
        firewall = AzureFirewall.from_dict(json.loads(resp))

        policy_ref = SubResource()
        policy_ref.id = resourceId
        firewall.firewall_policy = policy_ref
        resp = self.cl.put_resource(firewall.id, json.dumps(firewall.serialize()),  "2020-07-01")

