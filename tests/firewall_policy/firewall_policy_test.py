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

    def get_firewall_policy(self, resource_id):
        resp = self.cl.get_resource(resource_id, version.VERSION)
        return FirewallPolicy.from_dict(json.loads(resp))

    def put_firewall_policy(self, resource_id, policy):
        resourceJson = json.dumps(policy.serialize())
        resp = self.cl.put_resource(resource_id, resourceJson, version.VERSION)
        return resp

    def test_policy_with_ruleCollectionGroup(self, setup_rg, subscriptionId, location, resourceGroup):
        fp = FirewallPolicy()
        fp.location = location
        fp.resourceGroup = resourceGroup

        resourceId = '/subscriptions/' + subscriptionId + '/resourceGroups/' + resourceGroup + '/providers/Microsoft.Network/firewallPolicies/jammyFP01'
        resp = self.put_firewall_policy(resourceId, fp)

        rcg_resourceId = resourceId + '/ruleCollectionGroups/rcg01'
        rcg = FirewallPolicyRuleCollectionGroup()
        rcg.priority = 200
        rcg.rule_collections = []
        rc = FirewallPolicyRuleCollection()
        rc.rule_collection_type = 'FirewallPolicyFilterRuleCollection'
        rcg.rule_collections.append(rc)

        resourceJson = json.dumps(rcg.serialize())
        resp = self.cl.put_resource(rcg_resourceId, resourceJson, version.VERSION)

        updated_policy = self.get_firewall_policy(resourceId)

    def test_create_delete_vnet_fw(self, setup_rg, subscriptionId, location, resourceGroup):
        fp = FirewallPolicy()
        fp.location = location
        fp.resourceGroup = resourceGroup
        
        # first deploy the ARM template 
        template_file = os.path.join(os.path.dirname(__file__), 'templates', 'firewallPolicySandbox.json')
        self.cl.deploy_template(subscriptionId, "test-deployment", resourceGroup, location, template_file)
        
        # create firewall policy 
        resourceId = '/subscriptions/' + subscriptionId + '/resourceGroups/' + resourceGroup + '/providers/Microsoft.Network/firewallPolicies/jammyFP02'
        resp = self.put_firewall_policy(resourceId, fp)

        # create a rule collection group
        rcg_id = resourceId + '/ruleCollectionGroups/rcg01'

        net_rule = NetworkRule()
        net_rule.name = 'google_dns'
        net_rule.source_addresses = ['10.1.0.0/24']
        net_rule.destination_addresses = ['8.8.8.8', '8.8.8.4']
        net_rule.destination_ports = ["53"]
        net_rule.ip_protocols = [FirewallPolicyRuleNetworkProtocol.udp]
        rule_list = []
        rule_list.append(net_rule)
        
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
        rc.rules = rule_list
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

        # verify that the policy is associated with the firewall
        updated_policy = self.get_firewall_policy(resourceId) 

        assert len(updated_policy.firewalls) > 0 , "No firewalls associated with firewall policy"
        #update the policy rule settings

        import pdb ; pdb.set_trace()
        ftp_rule = NetworkRule()
        ftp_rule.name = 'ftp'
        ftp_rule.source_addresses = ['10.1.0.0/24']
        ftp_rule.destination_addresses = ['52.8.4.1', '80.1.18.4']
        ftp_rule.destination_ports = ["21"]
        ftp_rule.ip_protocols = [FirewallPolicyRuleNetworkProtocol.tcp]

        rule_list.append(ftp_rule)

        rcg = FirewallPolicyRuleCollectionGroup.from_dict(json.loads(self.cl.get_resource(rcg_id, version.VERSION)))
        rc = rcg.rule_collections[0]
        rc.rules = rule_list 

        resourceJson = json.dumps(rcg.serialize())
        resp = self.cl.put_resource(rcg_id, resourceJson, version.VERSION)
        
        


