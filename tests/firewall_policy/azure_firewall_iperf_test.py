"""
Tests for Azure Firewall Datapath
"""

import logging
import json
import os
import pytest
import random
from jammy.armclient import ArmClient
from jammy.exceptions import CommandError, CommandTimeout, JammyError
from jammy.jumpbox import JumpBox
from jammy.ubuntu import Ubuntu
from jammy.models.firewallPolicy import *
from jammy.models.ipgroups import *
from jammy.models.publicIPaddress import *

from jammy.models.azurefirewall import AzureFirewall

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

CLIENT_PRIVATE_IP="10.0.2.4"
SERVER_PRIVATE_IP="10.0.3.4"

class TestAzureFirewallDatapath:

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

    def test_iperf_single_tcp_conn_fw_datapath(self, setup_rg, subscriptionId, location, resourceGroup):
        fp = FirewallPolicy()
        fp.location = location
        fp.resourceGroup = resourceGroup
        resource_group_id = '/subscriptions/' + subscriptionId + '/resourceGroups/' + resourceGroup 
        
        # first deploy the ARM template 
        template_file = os.path.join(os.path.dirname(__file__), 'templates', 'firewallPolicyPerfSandbox.json')
        self.cl.deploy_template(subscriptionId, "perf-deployment", resourceGroup, location, template_file)
       
        logger.info("test_iperf_single_tcp_conn_fw_datapath Step 1: Deploying sandbox template succeeded")
        # create firewall policy 
        resourceId = resource_group_id + '/providers/Microsoft.Network/firewallPolicies/jammyFP02'
        resp = self.put_firewall_policy(resourceId, fp)

        # create a rule collection group
        rcg_id = resourceId + '/ruleCollectionGroups/rcg01'

        net_rule = NetworkRule()
        net_rule.name = 'allow_all'
        net_rule.source_addresses = ['*']
        net_rule.destination_addresses = ['*']
        net_rule.destination_ports = ['*']
        net_rule.ip_protocols = [FirewallPolicyRuleNetworkProtocol.any]
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

        logger.info("test_iperf_single_tcp_conn_fw_datapath  Step 2: Create FP with RuleCollectionGroup succeeded")
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
        logger.info("test_iperf_single_tcp_conn_fw_datapath: Step 3: Associate FP with Firewall succeeded")

        # now test datapath. 
        # 1. get the PIP address for the jumpbox

        jumpbox_pip_resource_id = resource_group_id + '/providers/Microsoft.Network/publicIPAddresses/' + 'JumpHostPublicIP'
        resp = self.cl.get_resource(jumpbox_pip_resource_id, "2022-01-01")
        publicIP = PublicIPAddress.from_dict(json.loads(resp))

        logger.info("Jumpbox PIP is [%s]", publicIP.ip_address)

        # 2. Now connect to the client machine via Jumpbox
        jumpbox = JumpBox()
        jumpbox.public_ip = publicIP.ip_address

        client_machine = Ubuntu()
        client_machine.username = "gsauser"
        client_machine.ssh_hop = jumpbox
        client_machine.private_ip = CLIENT_PRIVATE_IP
        client_machine.private_key_path = os.path.join(os.path.dirname(__file__), 'keys', 'jammytest.pem')

        server_machine = Ubuntu()
        server_machine.username = "gsauser"
        server_machine.ssh_hop = jumpbox
        server_machine.private_ip = SERVER_PRIVATE_IP
        server_machine.private_key_path = os.path.join(os.path.dirname(__file__), 'keys', 'jammytest.pem')
        
        # install iperf on the server
        try:
            result = server_machine.install('iperf')
        except CommandError:
            logger.info('Failed to install iperf on the server machine')
        # start the iperf server
        server_machine.exec_command('iperf -s -p 9000')

        # install iperf on the client
        try:
            result = client_machine.install('iperf')            
        except CommandError:
            logger.info('Failed to install iperf on the client machine')
        
        output, exit_status = client_machine.exec_command('iperf -p 9000 -c 10.0.3.4 -d | grep -o -E "[0-9]+ Mbits/sec"')
        logger.info('test_iperf_single_tcp_conn_fw_datapath: iperf result %s', output)
        for line in output.splitlines():
            parts = line.split(" ")
            if len(parts) >= 2:                
                logger.info("test_iperf_single_tcp_conn_fw_datapath: parts %s, %s", parts[0], parts[1])
                bandwidth = int(parts[0])
                assert bandwidth > 650, "Firewall standard SKU single TCP connection supported bandwidth dropped below 650 Mbps"

        logger.info("iperf datapath test to verify performance with 1 TCP connection succeeded")
        
