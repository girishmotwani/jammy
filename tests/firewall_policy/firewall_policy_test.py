"""
Tests for firewall policy in Jammy
"""

import logging
import json
import os
import pytest
import random
from jammy.armclient import ArmClient
from jammy.models.firewallPolicy import *
from jammy.models.ipgroups import *

from jammy.models.azurefirewall import AzureFirewall

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class TestFirewallPolicy:

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
        resp = self.cl.put_resource(rcg_resourceId, resourceJson, "2021-05-01")

        updated_policy = self.get_firewall_policy(resourceId)

    def test_create_delete_vhub_fw(self, setup_rg, subscriptionId, location, resourceGroup):
        fp = FirewallPolicy()
        fp.location = location
        fp.resourceGroup = resourceGroup
        resource_group_id = '/subscriptions/' + subscriptionId + '/resourceGroups/' + resourceGroup 
        
        # first deploy the ARM template 
        template_file = os.path.join(os.path.dirname(__file__), 'templates', 'firewallPolicyVhubSandbox.json')
        self.cl.deploy_template(subscriptionId, "test-deployment-vhub", resourceGroup, location, template_file)
       
        logger.info("test_create_delete_vhub_fw: Step 1: Deploying sandbox template succeeded")
        # create firewall policy 
        resourceId = resource_group_id + '/providers/Microsoft.Network/firewallPolicies/jammyFP03'
        resp = self.put_firewall_policy(resourceId, fp)

        # create a rule collection group
        rcg_resourceId = resourceId + '/ruleCollectionGroups/rcg01'
        rcg = FirewallPolicyRuleCollectionGroup()
        rcg.priority = 200
        rcg.rule_collections = []
        
        rc = FirewallPolicyRuleCollection()
        allow_action = FirewallPolicyFilterRuleCollectionAction()
        allow_action.type = "ALLOW"
        rc.name = "testRuleCollection01"
        rc.priority = 1000
        rc.action = allow_action
        rc.rule_collection_type = 'FirewallPolicyFilterRuleCollection'
        rule_list = []
        rule_list.append(self.create_network_rule("rule1", ["10.1.0.0/16"], ["8.8.8.8"], ["53"],[FirewallPolicyRuleNetworkProtocol.udp]))
        rule_list.append(self.create_network_rule("rule2", ["10.1.0.0/16"], ["8.8.8.4"], ["53"],[FirewallPolicyRuleNetworkProtocol.udp]))
        rule_list.append(self.create_network_rule("rule3", ["10.1.0.0/16"], ["8.8.8.4"], ["443"],[FirewallPolicyRuleNetworkProtocol.tcp]))
        rc.rules = rule_list
        
        rcg.rule_collections.append(rc)
        resourceJson = json.dumps(rcg.serialize())
        resp = self.cl.put_resource(rcg_resourceId, resourceJson, "2021-05-01")

        logger.info("test_create_delete_vhub_fw: Step 2: Create FP with RuleCollectionGroup succeeded")
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
        logger.info("test_create_delete_vhub_fw: Step 3: Associate FP with Firewall succeeded")

        #finally delete the resource group
        self.cl.delete_resource(resource_group_id, '2019-10-01')

    def test_create_delete_vnet_fw(self, setup_rg, subscriptionId, location, resourceGroup):
        fp = FirewallPolicy()
        fp.location = location
        fp.resourceGroup = resourceGroup
        resource_group_id = '/subscriptions/' + subscriptionId + '/resourceGroups/' + resourceGroup 
        
        # first deploy the ARM template 
        template_file = os.path.join(os.path.dirname(__file__), 'templates', 'firewallPolicySandbox.json')
        self.cl.deploy_template(subscriptionId, "test-deployment", resourceGroup, location, template_file)
       
        logger.info("test_create_delete_vnet_fw: Step 1: Deploying sandbox template succeeded")
        # create firewall policy 
        resourceId = resource_group_id + '/providers/Microsoft.Network/firewallPolicies/jammyFP02'
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
        logger.info("test_create_delete_vnet_fw: Step 3: Associate FP with Firewall succeeded")
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

    def test_firewall_policy_inheritence(self, subscriptionId, location, resourceGroup):
        resourceGroup = "inheritence" + resourceGroup

        self.cl = ArmClient()
        self.rg = self.cl.create_resource_group(subscriptionId, resourceGroup, location)

        fp = FirewallPolicy()
        fp.location = location
        fp.resourceGroup = resourceGroup
        resource_group_id = '/subscriptions/' + subscriptionId + '/resourceGroups/' + resourceGroup
        
        # first deploy the ARM template 
        template_file = os.path.join(os.path.dirname(__file__), 'templates', 'firewallPolicySandbox.json')
        self.cl.deploy_template(subscriptionId, "test-deployment-inheritence", resourceGroup, location, template_file)
        
        # create base firewall policy 
        resourceId = resource_group_id + '/providers/Microsoft.Network/firewallPolicies/jammyFPBase'
        childPolicyId = resource_group_id + '/providers/Microsoft.Network/firewallPolicies/jammyFPChild'
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
        #update the base policy rule settings

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

        #finally delete the resource group
        self.cl.delete_resource(resource_group_id, '2019-10-01')
     
    def put_ipg(self, resource_id, ipg):
        resourceJson = json.dumps(ipg.serialize())
        resp = self.cl.put_resource(resource_id, resourceJson, "2020-06-01")
        return resp

    def get_ip_addr_list(self, num):
        addr_list = []
        for i in range(0,num):
            ipaddr = '.'.join('%s'%random.randint(0, 255) for i in range(4))
            print(ipaddr)
            addr_list.append(ipaddr)
        return addr_list

    def create_ipgrp(self, name, subscription_id, location, resource_group, num_ips):
        self.cl = ArmClient()
        logger.info("IPG create: %s", name)
        ipg = IpGroup()
        ipg.location = location
        ipg.resourceGroup = resource_group
        ipg.ip_addresses = self.get_ip_addr_list(num_ips)
        resource_id = '/subscriptions/' + subscription_id + '/resourceGroups/' + resource_group + '/providers/Microsoft.Network/ipGroups/' + name
        resp = self.put_ipg(resource_id, ipg)
        logger.info("IPG created: %s", resource_id)
        return resource_id

    def get_rule_with_ipg(self, rulename,subscriptionId, location, resourceGroup):
        net_rule = NetworkRule()
        net_rule.name = rulename
        sr = self.create_ipgrp(rulename+"ipgs", subscriptionId, location, resourceGroup, 2)
        dr = self.create_ipgrp(rulename+"ipgd", subscriptionId, location, resourceGroup, 2)
        net_rule.source_ip_groups = [sr]
        net_rule.destination_ip_groups = [dr]
        net_rule.destination_ports = [str(random.randint(0, 64000))]
        net_rule.ip_protocols = [FirewallPolicyRuleNetworkProtocol.udp]
        return net_rule

    def get_rule_list(self, name, subscription_id, location, resource_group, num_rules):
        rule_list = []
        for i in range(0, num_rules):
            rule_list.append(self.get_rule_with_ipg(name + 'rule' + str(i), subscription_id, location, resource_group))
        return rule_list

    def get_rule_list_mul_subs(self, name, subscription_ids, location, resource_group, num_rules):
        rule_list = []
        j = 0
        for i in range(0, num_rules):
            if j >= len(subscription_ids):
                j = 0
            rule_list.append(self.get_rule_with_ipg(name + 'rule' + str(i), subscription_ids[j], location, resource_group))
            j = j + 1
        return rule_list

    def test_create_delete_vnet_fw_with_ipg(self, setup_rg, subscriptionId, location, resourceGroup, num_rcg, num_rc,
                                            num_rules):
        self.cl = ArmClient()
        fp = FirewallPolicy()
        fp.location = location
        fp.resourceGroup = resourceGroup
        resource_group_id = '/subscriptions/' + subscriptionId + '/resourceGroups/' + resourceGroup
        
        # first deploy the ARM template 
        template_file = os.path.join(os.path.dirname(__file__), 'templates', 'firewallPolicySandbox.json')
        self.cl.deploy_template(subscriptionId, "test-deployment", resourceGroup, location, template_file)
        logger.info("test_create_delete_vnet_fw_with_ipg: Step 1: Deploying sandbox template succeeded")

        # create firewall policy 
        resourceId = resource_group_id + '/providers/Microsoft.Network/firewallPolicies/jammyFPIPG'
        resp = self.put_firewall_policy(resourceId, fp)
        logger.info("test_create_delete_vnet_fw_with_ipg: Step 2: Created FW Policy")
        # create rule collection groups
        for i in range(0, int(num_rcg)):
            rcg = FirewallPolicyRuleCollectionGroup()
            rcg.priority = 201 + i
            rcg.rule_collections = []
            for j in range(0, int(num_rc)):
                rc = FirewallPolicyFilterRuleCollection()
                allow_action = FirewallPolicyFilterRuleCollectionAction()
                allow_action.type = "ALLOW"
                rc.rule_collection_type = 'FirewallPolicyFilterRuleCollection'
                rc.name = "RCG" + str(i) + "rl" + str(j)
                rc.priority = 1000+j
                rc.action = allow_action
                rc.rules = self.get_rule_list(rc.name, subscriptionId, location, resourceGroup, int(num_rules))
                rcg.rule_collections.append(rc)
            logger.info("test_create_delete_vnet_fw_with_ipg: Step 3.%s: Sending Arm request to add RCG", i)
            rcg_id = resourceId + '/ruleCollectionGroups/rcg' + str(i)
            resourceJson = json.dumps(rcg.serialize())
            resp = self.cl.put_resource(rcg_id, resourceJson, "2020-06-01")
            logger.info("test_create_delete_vnet_fw_with_ipg: Step 3.%s: Completed Arm request to add RCG:%s", i, rcg_id)
        logger.info("test_create_delete_vnet_fw_with_ipg: Step 3: Completed updating FW policy with RCGs")

        logger.info("test_create_delete_vnet_fw_with_ipg: Step 4: Get FW")
        fw_resource_id = resource_group_id + '/providers/Microsoft.Network/azureFirewalls/' + 'firewall1'
        resp = self.cl.get_resource(fw_resource_id, "2020-07-01")
        firewall = AzureFirewall.from_dict(json.loads(resp))
        logger.info("test_create_delete_vnet_fw_with_ipg: Step 4: Completed Get FW")

        logger.info("test_create_delete_vnet_fw_with_ipg: Step 5: Associate FW Policy and Firewall")
        policy_ref = SubResource()
        policy_ref.id = resourceId
        firewall.firewall_policy = policy_ref
        resp = self.cl.put_resource(firewall.id, json.dumps(firewall.serialize()),  "2020-07-01")
        logger.info("test_create_delete_vnet_fw_with_ipg: Step 5: Completed Associate FW Policy and Firewall")

        # verify that the policy is associated with the firewall
        updated_policy = self.get_firewall_policy(resourceId)
        assert len(updated_policy.firewalls) > 0 , "No firewalls associated with firewall policy"

        # finally delete the resource group
        self.cl.delete_resource(resource_group_id, '2019-10-01')

    def create_rcg(self, num_rc, num_rules, rcg_index):
        rcg = FirewallPolicyRuleCollectionGroup()
        rcg.priority = 201 + rcg_index
        rcg.rule_collections = []
        for j in range(0, int(num_rc)):
            rc = FirewallPolicyFilterRuleCollection()
            allow_action = FirewallPolicyFilterRuleCollectionAction()
            allow_action.type = "ALLOW"
            rc.rule_collection_type = 'FirewallPolicyFilterRuleCollection'
            rc.name = "RCG" + str(rcg_index) + "rl" + str(j)
            rc.priority = 1000 + j
            rc.action = allow_action
            rc.rules = []
            for k in range(0, int(num_rules)):
                net_rule = NetworkRule()
                net_rule.name = 'rule' + str(k)
                net_rule.source_addresses = self.get_ip_addr_list(1)
                net_rule.destination_addresses = self.get_ip_addr_list(1)
                net_rule.destination_ports = [str(random.randint(1, 64000))]
                net_rule.ip_protocols = [FirewallPolicyRuleNetworkProtocol.udp]
                rc.rules.append(net_rule)
            rcg.rule_collections.append(rc)
        return rcg

    def test_create_update_delete_large_rcg(self, setup_rg, subscriptionId, location, resourceGroup):
        num_rcg = 2
        num_rc = 5
        num_rules = 1
        self.cl = ArmClient()
        fp = FirewallPolicy()
        fp.location = location
        fp.resourceGroup = resourceGroup
        resource_group_id = '/subscriptions/' + subscriptionId + '/resourceGroups/' + resourceGroup

        # first deploy the ARM template
        template_file = os.path.join(os.path.dirname(__file__), 'templates', 'firewallPolicySandbox.json')
        self.cl.deploy_template(subscriptionId, "test-deployment", resourceGroup, location, template_file)
        logger.info("test_create_update_delete_large_rcg: Step 1: Deploying sandbox template succeeded")

        # create firewall policy
        resourceId = resource_group_id + '/providers/Microsoft.Network/firewallPolicies/jammyFPIP'
        resp = self.put_firewall_policy(resourceId, fp)
        logger.info("test_create_update_delete_large_rcg: Step 2: Created FW Policy")
        # create rule collection groups
        for i in range(0, int(num_rcg)):
            rcg = self.create_rcg(num_rc, num_rules, i)
            logger.info("test_create_update_delete_large_rcg: Step 3.%s: Sending Arm request to add RCG", i)
            rcg_id = resourceId + '/ruleCollectionGroups/rcg' + str(i)
            resourceJson = json.dumps(rcg.serialize())
            resp = self.cl.put_resource(rcg_id, resourceJson, "2020-06-01")
            logger.info("test_create_update_delete_large_rcg: Step 3.%s: Completed Arm request to add  RCG:%s", i,
                        rcg_id)
        logger.info("test_create_update_delete_large_rcg: Step 3: Completed updating FW policy with RCGs")

        logger.info("test_create_update_delete_large_rcg: Step 4: Get FW")
        fw_resource_id = resource_group_id + '/providers/Microsoft.Network/azureFirewalls/' + 'firewall1'
        resp = self.cl.get_resource(fw_resource_id, "2020-07-01")
        firewall = AzureFirewall.from_dict(json.loads(resp))
        logger.info("test_create_delete_vnet_fw_with_ipg: Step 4: Completed Get FW")

        logger.info("test_create_update_delete_large_rcg: Step 5: Associate FW Policy and Firewall")
        policy_ref = SubResource()
        policy_ref.id = resourceId
        firewall.firewall_policy = policy_ref
        resp = self.cl.put_resource(firewall.id, json.dumps(firewall.serialize()), "2020-07-01")
        logger.info("test_create_update_delete_large_rcg: Step 5: Completed Associate FW Policy and Firewall")

        # verify that the policy is associated with the firewall
        updated_policy = self.get_firewall_policy(resourceId)
        assert len(updated_policy.firewalls) > 0, "No firewalls associated with firewall policy"
        assert firewall.provisioning_state == 'Succeeded', "Firewall provisioning state is not Succeeded"

        logger.info("test_create_update_delete_large_rcg: Step 6: Update FW policy RCG")
        resp = self.cl.get_resource(rcg_id, "2020-06-01")
        rcg = FirewallPolicyRuleCollectionGroup.from_dict(json.loads(resp))
        rcg.priority = 500
        resourceJson = json.dumps(rcg.serialize())
        resp = self.cl.put_resource(rcg_id, resourceJson, "2020-06-01")

        logger.info("test_create_update_delete_large_rcg: Step 7: GET RCG and verify update and FW state")
        resp = self.cl.get_resource(rcg_id, "2020-06-01")
        rcg = FirewallPolicyRuleCollectionGroup.from_dict(json.loads(resp))
        assert rcg.priority == 500, "RCG was not updated successfully"
        resp = self.cl.get_resource(fw_resource_id, "2020-07-01")
        firewall = AzureFirewall.from_dict(json.loads(resp))
        assert firewall.provisioning_state == 'Succeeded', "Firewall provisioning state is not Succeeded"

        # finally delete the resource group
        # self.cl.delete_resource(resource_group_id, '2019-10-01')

    
    def test_create_delete_vnet_fw_with_ipg_multiple_subscriptions(self, setup_rg, subscriptionId, location, resourceGroup, subscriptionIds, num_rcg, num_rc,
                                            num_rules):
        
        
        self.cl = ArmClient()
        fp = FirewallPolicy()
        fp.location = location
        fp.resourceGroup = resourceGroup
        resource_group_id = '/subscriptions/' + subscriptionId + '/resourceGroups/' + resourceGroup

        if subscriptionIds is None:
            subscriptionIds = []
            subscriptionIds.append(subscriptionId)
        
        # first deploy the ARM template 
        template_file = os.path.join(os.path.dirname(__file__), 'templates', 'firewallPolicySandbox.json')
        for subscriptionId in subscriptionIds:
            self.cl.deploy_template(subscriptionId, "test-deployment", resourceGroup, location, template_file)
        logger.info("test_create_delete_vnet_fw_with_ipg_multiple_subscriptions: Step 1: Deploying sandbox template succeeded")

        # create firewall policy 
        resourceId = resource_group_id + '/providers/Microsoft.Network/firewallPolicies/jammyFPIPG'
        resp = self.put_firewall_policy(resourceId, fp)
        logger.info("test_create_delete_vnet_fw_with_ipg_multiple_subscriptions: Step 2: Created FW Policy")
        # create rule collection groups
        for i in range(0, int(num_rcg)):
            rcg = FirewallPolicyRuleCollectionGroup()
            rcg.priority = 201 + i
            rcg.rule_collections = []
            for j in range(0, int(num_rc)):
                rc = FirewallPolicyFilterRuleCollection()
                allow_action = FirewallPolicyFilterRuleCollectionAction()
                allow_action.type = "ALLOW"
                rc.rule_collection_type = 'FirewallPolicyFilterRuleCollection'
                rc.name = "RCG" + str(i) + "rl" + str(j)
                rc.priority = 1000+j
                rc.action = allow_action
                rc.rules = self.get_rule_list_mul_subs(rc.name, subscriptionIds, location, resourceGroup, int(num_rules))
                rcg.rule_collections.append(rc)
            logger.info("test_create_delete_vnet_fw_with_ipg_multiple_subscriptions: Step 3.%s: Sending Arm request to add RCG", i)
            rcg_id = resourceId + '/ruleCollectionGroups/rcg' + str(i)
            resourceJson = json.dumps(rcg.serialize())
            resp = self.cl.put_resource(rcg_id, resourceJson, "2020-06-01")
            logger.info("test_create_delete_vnet_fw_with_ipg_multiple_subscriptions: Step 3.%s: Completed Arm request to add RCG:%s", i, rcg_id)
        logger.info("test_create_delete_vnet_fw_with_ipg_multiple_subscriptions: Step 3: Completed updating FW policy with RCGs")

        logger.info("test_create_delete_vnet_fw_with_ipg_multiple_subscriptions: Step 4: Get FW")
        fw_resource_id = resource_group_id + '/providers/Microsoft.Network/azureFirewalls/' + 'firewall1'
        resp = self.cl.get_resource(fw_resource_id, "2020-07-01")
        firewall = AzureFirewall.from_dict(json.loads(resp))
        logger.info("test_create_delete_vnet_fw_with_ipg_multiple_subscriptions: Step 4: Completed Get FW")

        logger.info("test_create_delete_vnet_fw_with_ipg_multiple_subscriptions: Step 5: Associate FW Policy and Firewall")
        policy_ref = SubResource()
        policy_ref.id = resourceId
        firewall.firewall_policy = policy_ref
        resp = self.cl.put_resource(firewall.id, json.dumps(firewall.serialize()),  "2020-07-01")
        logger.info("test_create_delete_vnet_fw_with_ipg_multiple_subscriptions: Step 5: Completed Associate FW Policy and Firewall")

        # verify that the policy is associated with the firewall
        updated_policy = self.get_firewall_policy(resourceId)
        assert len(updated_policy.firewalls) > 0 , "No firewalls associated with firewall policy"

        #finally delete the resource group
        #self.cl.delete_resource(resource_group_id, '2019-10-01')   


