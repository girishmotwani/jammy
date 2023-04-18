"""
Tests for ip group in Jammy
"""

import logging
import json
import os
import pytest
import random
import time
import datetime
import threading
from jammy.armclient import ArmClient
from jammy.models.firewallPolicy import *
from jammy.models.ipgroups import *
from jammy.models.azurefirewall import AzureFirewall


from utils.firewallpolicyutil import FirewallPolicyUtil
from utils.rulecollectiongrouputil import RuleCollectionGroupUtil
from utils.firewallutil import FirewallUtil

from utils.ipgrouputil import IpGroupUtil

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

result = []

class TestIPGroup:

    @pytest.fixture
    def setup_rg(self, subscriptionId, resourceGroup, location):
        self._cl = ArmClient()
        self._rg = self._cl.create_resource_group(subscriptionId, resourceGroup, location)
        self._subscription_id = subscriptionId
        self._location = location
        self._resourceGroup = resourceGroup

    def get_resource_group_id(self):
        return '/subscriptions/' + self._subscription_id + '/resourceGroups/' + self._resourceGroup

    def test_delete_vnet_fw_with_ipg(self, setup_rg, subscriptionId, location, resourceGroup):
        # finally delete the resource group
        self._cl.delete_resource(self.get_resource_group_id(), '2019-10-01')

    def test_create_vnet_fw_with_ipg(self, setup_rg, subscriptionId, location, resourceGroup, num_rcg, num_rc,
                                            num_rules):
        fwp_util = FirewallPolicyUtil(subscriptionId, location, resourceGroup, self._cl)
        rcg_util = RuleCollectionGroupUtil(subscriptionId, location, resourceGroup, self._cl)
        fw_util = FirewallUtil(subscriptionId, location, resourceGroup, self._cl)

        # first deploy the ARM template
        logger.info("test_create_delete_vnet_fw_with_ipg: Step 1: Deploying sandbox template")
        template_file = os.path.join(os.path.dirname(__file__), '../firewall_policy/templates','firewallPolicySandbox.json')
        self._cl.deploy_template(subscriptionId, "test-deployment", resourceGroup, location, template_file)
        logger.info("test_create_delete_vnet_fw_with_ipg: Step 1: Deploying sandbox template succeeded")

        # create firewall policy
        logger.info("test_create_delete_vnet_fw_with_ipg: Step 2: Creating FW policy")
        fwp_resource_id = fwp_util.get_resource_id('jammyFPIPG')
        fwp = fwp_util.create_firewall_policy(fwp_util.get_resource_id('jammyFPIPG'))
        logger.info("test_create_delete_vnet_fw_with_ipg: Step 2: Creating FW policy succeeded")

        # create rule collection groups
        for i in range(0, int(num_rcg)):
            rcg = rcg_util.build_rcg(num_rc, num_rules, i, True)
            rcg_resource_id = rcg_util.get_resource_id(fwp_resource_id, 'rcg'+str(i))
            logger.info("test_create_delete_vnet_fw_with_ipg: Step 3.%s: Creating RCG:%s", i,
                        rcg_resource_id)
            resp = rcg_util.put(rcg_resource_id, rcg)
            time.sleep(15)
            logger.info("test_create_delete_vnet_fw_with_ipg: Step 3.%s: Completed Arm request to add RCG:%s", i,
                        rcg_resource_id)
        logger.info("test_create_delete_vnet_fw_with_ipg: Step 3: Completed updating FW policy with RCGs")

        logger.info("test_create_delete_vnet_fw_with_ipg: Step 4: Get FW")
        fw_resource_id = fw_util.get_resource_id('firewall1')
        firewall = fw_util.get(fw_resource_id)
        logger.info("test_create_delete_vnet_fw_with_ipg: Step 4: Completed Get FW")

        logger.info("test_create_delete_vnet_fw_with_ipg: Step 5: Associate FW Policy and Firewall")
        resp = fw_util.associate_policy(firewall, fwp_resource_id)
        logger.info("test_create_delete_vnet_fw_with_ipg: Step 5: Completed Associate FW Policy and Firewall")

        # verify that the policy is associated with the firewall
        updated_policy = fwp_util.get(fwp_resource_id)
        assert len(updated_policy.firewalls) > 0, "No firewalls associated with firewall policy"

    def update_ipg_thread(self, ipg_resource_id, add_ips, del_ips, t_num, tag):
        global result
        logger.info("test_ipg_update_parallel: Started update for IPG:%s", ipg_resource_id)
        start_time_str = time.ctime()
        start_time = time.time()
        print(str(start_time_str), "Started update for IPG:", ipg_resource_id)
        ipg_util = IpGroupUtil(self._subscription_id, self._location, self._resourceGroup, ArmClient())
        resp = ipg_util.update_ipg(ipg_resource_id, add_ips, del_ips, tag)
        if resp == 'Succeeded':
            result[t_num] = "Succeeded"
        logger.info("test_ipg_update_parallel: Completed update for IPG:%s Resp:%s", ipg_resource_id, resp)
        end_time_str = time.ctime()
        end_time = time.time()
        print(end_time_str, "Completed update for IPG:", ipg_resource_id, "Resp", resp)
        total_time = end_time - start_time
        print("========>TOTAL TIME", total_time, "(sec)<========= for IPG:", ipg_resource_id)

        return resp

    def test_ipg_update_parallel(self, setup_rg, subscriptionId, location, resourceGroup, num_rcg, num_rc, num_rules):
        ipg_util = IpGroupUtil(subscriptionId, location, resourceGroup, self._cl)
        ipg_update_jobs = []
        global result

        t_num = 0
        logger.info("test_ipg_update_parallel: Result: %s", result)

        for rcg_index in range(0, int(num_rcg)):
            for rc_index in range(0, int(num_rc)):
                for rules_index in range(0, int(num_rules)):
                    ids = ipg_util.get_ipg_resource_id(rcg_index, rc_index, rules_index, "ipgs")
                    idd = ipg_util.get_ipg_resource_id(rcg_index, rc_index, rules_index, "ipgd")
                    tag_s = ipg_util.get_ipg_tag(rcg_index, rc_index, rules_index, "ipgs")
                    tag_d = ipg_util.get_ipg_tag(rcg_index, rc_index, rules_index, "ipgd")
                    result.append("Failed")
                    thread = threading.Thread(target=self.update_ipg_thread, args=(ids, ["1.2.3.4"], [],
                                                                                    t_num, tag_s))
                    t_num = t_num + 1
                    ipg_update_jobs.append(thread)
                    result.append("Failed")
                    thread = threading.Thread(target=self.update_ipg_thread, args=(idd, ["1.2.3.4"], [],
                                                                                    t_num, tag_d))
                    t_num = t_num + 1
                    ipg_update_jobs.append(thread)

        # Start the threads
        for thread in ipg_update_jobs:
            thread.start()
            time.sleep(1)
        logger.info("Started all ip group update threads")

        # Ensure all of the threads have finished
        for thread in ipg_update_jobs:
            thread.join()

        logger.info("completed all ip group update threads")
        logger.info("test_ipg_update_parallel: Result: %s", result)
        assert [r for r in result if r == "Succeeded"], 'IP Groups failed to update'

    def test_create_policy_with_ipg(self, setup_rg, subscriptionId, location, resourceGroup, num_rcg, num_rc,
                                            num_rules):
        fwp_util = FirewallPolicyUtil(subscriptionId, location, resourceGroup, self._cl)
        rcg_util = RuleCollectionGroupUtil(subscriptionId, location, resourceGroup, self._cl)
        fw_util = FirewallUtil(subscriptionId, location, resourceGroup, self._cl)

        # create rule collection groups
        for i in range(0, int(num_rcg)):
            rcg = rcg_util.build_rcg(num_rc, num_rules, i, True)
            rcg_resource_id = rcg_util.get_resource_id(fwp_resource_id, 'rcg'+str(i))
            logger.info("test_create_policy_with_ipg: Step 1.%s: Creating RCG:%s", i,
                        rcg_resource_id)
            resp = rcg_util.put(rcg_resource_id, rcg)
            logger.info("test_create_delete_vnet_fw_with_ipg: Step 1.%s: Completed Arm request to add RCG:%s", i,
                        rcg_resource_id)
        logger.info("test_create_policy_with_ipg: Step 1: Completed updating FW policy with RCGs")
