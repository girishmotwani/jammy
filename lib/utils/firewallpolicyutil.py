"""
Utils for firewall policy
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


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)




class FirewallPolicyUtil:

    def __init__(self, sub, loc, rg, cl):
        self._subscription_id = sub
        self._location = loc
        self._resourceGroup = rg
        self._cl = cl

    def get(self, resource_id):
        resp = self._cl.get_resource(resource_id, "2021-05-01")
        return FirewallPolicy.from_dict(json.loads(resp))

    def put(self, resource_id, policy):
        resourceJson = json.dumps(policy.serialize())
        resp = self._cl.put_resource(resource_id, resourceJson, "2021-05-01")
        return resp

    def get_resource_id(self, fwp_name):
        return '/subscriptions/' + self._subscription_id + '/resourceGroups/' + self._resourceGroup \
                + '/providers/Microsoft.Network/firewallPolicies/' + fwp_name

    def create_firewall_policy(self, resource_id, num_rcg, num_rc, num_rules, ipgFlag=False ):
        # create firewall policy
        fp = FirewallPolicy()
        fp.location = self._location
        fp.resourceGroup = self._resourceGroup

        resp = self.put(resource_id, fp)
        logger.info("Created FW Policy")

        rcg_util = RuleCollectionGroupUtil(self._subscription_id, self._location, self._resourceGroup, self._cl)
        # create rule collection groups
        for i in range(0, int(num_rcg)):
            rcg = rcg_util.build_rcg(num_rc, num_rules, i, ipgFlag)
            logger.info("Sending Arm request to add RCG: %s", i)
            rcg_id = resource_id + '/ruleCollectionGroups/rcg' + str(i)
            resourceJson = json.dumps(rcg.serialize())
            resp = self._cl.put_resource(rcg_id, resourceJson, "2020-06-01")
            logger.info("Completed Arm request to add RCG:%s",
                        rcg_id)
        logger.info("Completed updating FW policy with RCGs")
        return fp

    def create_firewall_policy(self, resource_id):
        # create firewall policy
        fp = FirewallPolicy()
        fp.location = self._location
        fp.resourceGroup = self._resourceGroup

        resp = self.put(resource_id, fp)
        logger.info("Created FW Policy")
        return fp

