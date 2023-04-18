"""
Utils for firewall policy Rule Collection Group
"""

import logging
import json
import os
import pytest
import random
import time
import threading
from jammy.armclient import ArmClient
from jammy.models.firewallPolicy import *

from utils.ipgrouputil import IpGroupUtil

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class RuleCollectionGroupUtil:

    def __init__(self, sub, loc, rg, cl):
        self._subscription_id = sub
        self._location = loc
        self._resourceGroup = rg
        self._cl = cl

    def get(self, resource_id):
        resp = self._cl.get_resource(resource_id, "2021-05-01")
        return FirewallPolicy.from_dict(json.loads(resp))

    def put(self, resource_id, rcg):
        resourceJson = json.dumps(rcg.serialize())
        resp = self._cl.put_resource(resource_id, resourceJson, "2021-05-01")
        return resp

    def get_resource_id(self, fwp_resource_id, rcg_name):
        return fwp_resource_id + '/ruleCollectionGroups/' + rcg_name

    def build_rcg(self, num_rc, num_rules, rcg_index, ipg_flag=False):
        ipg_util = IpGroupUtil(self._subscription_id, self._location, self._resourceGroup, self._cl)
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
            if ipg_flag:
                rc.rules = ipg_util.get_rule_list(rc.name,
                                              int(num_rules))
            else:
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
