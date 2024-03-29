"""
Tests for firewall policy in Jammy
"""

import logging
import json
import os
import pytest
from jammy.armclient import *
from jammy.models.firewallPolicy import *

from jammy.models.azurefirewall import AzureFirewall

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class TestBasicSkuFirewall:

    cl = None

    @pytest.fixture
    def setup_rg(self, subscriptionId, resourceGroup, location):  
        self.cl = ArmClient()
        self.rg = self.cl.create_resource_group(subscriptionId, resourceGroup, location)

    def get_firewall_policy(self, resource_id):
        resp = self.cl.get_resource(resource_id, "2021-05-01")
        return FirewallPolicy.from_dict(json.loads(resp))

    def put_firewall_policy(self, resource_id, policy):
        resourceJson = json.dumps(policy.serialize())
        resp = self.cl.put_resource(resource_id, resourceJson, "2021-05-01")
        return resp

    def create_network_rule(self, rule_name, src_addresses, dest_addresses, ports, protocols):
        net_rule = NetworkRule()
        net_rule.name = rule_name 
        net_rule.source_addresses = src_addresses
        net_rule.destination_addresses = dest_addresses
        net_rule.destination_ports = ports 
        net_rule.ip_protocols = protocols 
        return net_rule 

    def test_create_delete_basic_fw(self, setup_rg, subscriptionId, location, policyLocation, resourceGroup):
        fp = FirewallPolicy()
        fp.location = policyLocation
        fp.resourceGroup = resourceGroup

        sku = FirewallPolicySku()
        sku.tier = "Basic"
        fp.sku = sku

        resource_group_id = '/subscriptions/' + subscriptionId + '/resourceGroups/' + resourceGroup 
        
        # first deploy the ARM template 
        template_file = os.path.join(os.path.dirname(__file__), 'templates', 'firewallBasicSkuSandbox.json')
        self.cl.deploy_template(subscriptionId, "basicsku-deployment", resourceGroup, location, template_file)
       
        logger.info("test_create_delete_basic_fw: Step 1: Deploying sandbox template succeeded")
        # create firewall policy 
        resourceId = resource_group_id + '/providers/Microsoft.Network/firewallPolicies/basicFP02'
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
        resp = self.cl.put_resource(rcg_id, resourceJson, "2021-05-01")

        logger.info("test_create_delete_vnet_fw: Step 2: Create FP with RuleCollectionGroup succeeded")
        # now associate the firewall policy with the firewall deployed.
        fw_resourceId = resource_group_id + '/providers/Microsoft.Network/azureFirewalls/' + 'firewall1' 
        resp = self.cl.get_resource(fw_resourceId , "2020-07-01")
        firewall = AzureFirewall.from_dict(json.loads(resp))

        policy_ref = SubResource()
        policy_ref.id = resourceId
        firewall.firewall_policy = policy_ref
        resp = self.cl.put_resource(firewall.id, json.dumps(firewall.serialize()),  "2020-07-01")

        # verify that the policy is associated with the firewall
        updated_policy = self.get_firewall_policy(resourceId) 

        assert len(updated_policy.firewalls) > 0 , "No firewalls associated with firewall policy"
        logger.info("test_create_delete_basic_fw: Step 3: Associate FP with Firewall succeeded")
        #update the policy rule settings

        ftp_rule = NetworkRule()
        ftp_rule.name = 'ftp'
        ftp_rule.source_addresses = ['10.1.0.0/24']
        ftp_rule.destination_addresses = ['52.8.4.1', '80.1.18.4']
        ftp_rule.destination_ports = ["21"]
        ftp_rule.ip_protocols = [FirewallPolicyRuleNetworkProtocol.tcp]

        rule_list.append(ftp_rule)

        rcg = FirewallPolicyRuleCollectionGroup.from_dict(json.loads(self.cl.get_resource(rcg_id, "2021-05-01")))
        rc = rcg.rule_collections[0]
        rc.rules = rule_list 

        resourceJson = json.dumps(rcg.serialize())
        resp = self.cl.put_resource(rcg_id, resourceJson, "2021-05-01")

        assert (self.get_firewall_policy(resourceId)).provisioning_state == 'Succeeded', "Policy in failed state post update"
        logger.info("test_create_delete_vnet_fw: Step 4: Update Firewall Policy succeeded")

        #finally delete the resource group
        self.cl.delete_resource(resource_group_id, '2019-10-01')

    def test_basic_sku_policy_inheritance(self, subscriptionId, location, policyLocation, resourceGroup):
        resourceGroup = "inheritance" + resourceGroup

        self.cl = ArmClient()
        self.rg = self.cl.create_resource_group(subscriptionId, resourceGroup, location)

        fp = FirewallPolicy()
        fp.location = policyLocation
        fp.resourceGroup = resourceGroup
        sku = FirewallPolicySku()
        sku.tier = "Basic"
        fp.sku = sku
        
        resource_group_id = '/subscriptions/' + subscriptionId + '/resourceGroups/' + resourceGroup
        
        # first deploy the ARM template 
        template_file = os.path.join(os.path.dirname(__file__), 'templates', 'firewallBasicSkuSandbox.json')
        self.cl.deploy_template(subscriptionId, "test-deployment-inheritance", resourceGroup, location, template_file)
        
        # create base firewall policy 
        resourceId = resource_group_id + '/providers/Microsoft.Network/firewallPolicies/jammyFPBase'
        childPolicyId = resource_group_id + '/providers/Microsoft.Network/firewallPolicies/jammyFPChild'
        resp = self.put_firewall_policy(resourceId, fp)
        
        # create child policy, with reference of base policy resource set
        base_policy_ref = SubResource()
        base_policy_ref.id = resourceId
        fp.base_policy = base_policy_ref
        resp = self.put_firewall_policy(childPolicyId, fp)
        
        # now associate the firewall policy with the firewall deployed.
        fw_resourceId = resource_group_id + '/providers/Microsoft.Network/azureFirewalls/' + 'firewall1' 
        resp = self.cl.get_resource(fw_resourceId , "2020-07-01")
        firewall = AzureFirewall.from_dict(json.loads(resp))

        policy_ref = SubResource()
        policy_ref.id = childPolicyId
        firewall.firewall_policy = policy_ref
        resp = self.cl.put_resource(firewall.id, json.dumps(firewall.serialize()),  "2020-07-01")

        # verify that the policy is associated with the firewall
        updated_policy = self.get_firewall_policy(childPolicyId) 

        assert len(updated_policy.firewalls) > 0 , "No firewalls associated with firewall policy"
        
        #finally delete the resource group
        self.cl.delete_resource(resource_group_id, '2019-10-01')

    def test_basic_sku_policy_inheritance_error(self, subscriptionId, location, policyLocation, resourceGroup):
        resourceGroup = "inherit_error" + resourceGroup

        #create resource group
        self.cl = ArmClient()
        self.rg = self.cl.create_resource_group(subscriptionId, resourceGroup, location)

        fp = FirewallPolicy()
        fp.location = policyLocation
        fp.resourceGroup = resourceGroup
        
        resource_group_id = '/subscriptions/' + subscriptionId + '/resourceGroups/' + resourceGroup
        
        # create base firewall policy with Standard SKU 
        resourceId = resource_group_id + '/providers/Microsoft.Network/firewallPolicies/jammyFPBase'
        childPolicyId = resource_group_id + '/providers/Microsoft.Network/firewallPolicies/jammyFPChild'
        resp = self.put_firewall_policy(resourceId, fp)
        
        # create child policy, with reference of base policy resource set
        base_policy_ref = SubResource()
        base_policy_ref.id = resourceId
        fp.base_policy = base_policy_ref
        sku = FirewallPolicySku()
        sku.tier = "Basic"
        fp.sku = sku
        with pytest.raises(ArmClientError):
            resp = self.put_firewall_policy(childPolicyId, fp)
       
    def test_basic_sku_vhub_firewall_cp(self, subscriptionId, location, policyLocation, resourceGroup):
        resourceGroup = "vhub_" + resourceGroup

        # create resource group
        self.cl = ArmClient()
        self.rg = self.cl.create_resource_group(subscriptionId, resourceGroup, location)

        fp = FirewallPolicy()
        fp.location = policyLocation
        fp.resourceGroup = resourceGroup
        sku = FirewallPolicySku()
        sku.tier = "Basic"
        fp.sku = sku

        resource_group_id = '/subscriptions/' + subscriptionId + '/resourceGroups/' + resourceGroup 
        
        # first deploy the ARM template 
        template_file = os.path.join(os.path.dirname(__file__), 'templates', 'firewallPolicyVhubBASICSKUSandbox.json')
        self.cl.deploy_template(subscriptionId, "basicsku-deployment", resourceGroup, location, template_file)
       
        logger.info("test_basic_sku_vhub_firewall_cp: Step 1: Deploying sandbox template succeeded")
        # create firewall policy 
        resourceId = resource_group_id + '/providers/Microsoft.Network/firewallPolicies/basicFP02'
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
        resp = self.cl.put_resource(rcg_id, resourceJson, "2021-05-01")

        logger.info("test_basic_sku_vhub_firewall_cp: Step 2: Create FP, RCG succeeded")
        # now associate the firewall policy with the firewall deployed.
        fw_resourceId = resource_group_id + '/providers/Microsoft.Network/azureFirewalls/' + 'firewall1' 
        resp = self.cl.get_resource(fw_resourceId , "2020-07-01")
        firewall = AzureFirewall.from_dict(json.loads(resp))

        policy_ref = SubResource()
        policy_ref.id = resourceId
        firewall.firewall_policy = policy_ref
        resp = self.cl.put_resource(firewall.id, json.dumps(firewall.serialize()),  "2020-07-01")

        # verify that the policy is associated with the firewall
        updated_policy = self.get_firewall_policy(resourceId) 

        assert len(updated_policy.firewalls) > 0 , "No firewalls associated with firewall policy"
        logger.info("test_basic_sku_vhub_firewall_cp: Step 3: Associate FP with Firewall succeeded")
        #update the policy rule settings

        ftp_rule = NetworkRule()
        ftp_rule.name = 'ftp'
        ftp_rule.source_addresses = ['10.1.0.0/24']
        ftp_rule.destination_addresses = ['52.8.4.1', '80.1.18.4']
        ftp_rule.destination_ports = ["21"]
        ftp_rule.ip_protocols = [FirewallPolicyRuleNetworkProtocol.tcp]

        rule_list.append(ftp_rule)

        rcg = FirewallPolicyRuleCollectionGroup.from_dict(json.loads(self.cl.get_resource(rcg_id, "2021-05-01")))
        rc = rcg.rule_collections[0]
        rc.rules = rule_list 

        resourceJson = json.dumps(rcg.serialize())
        resp = self.cl.put_resource(rcg_id, resourceJson, "2021-05-01")

        assert (self.get_firewall_policy(resourceId)).provisioning_state == 'Succeeded', "Policy in failed state post update"
        logger.info("test_basic_sku_vhub_firewall_cp: Step 4: Update Firewall Policy succeeded")

        #finally delete the resource group
        self.cl.delete_resource(resource_group_id, '2019-10-01')
