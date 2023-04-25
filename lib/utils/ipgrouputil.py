"""
Utils for firewall policy Rule Collection Group
"""

import logging
import json
import random
import time
from jammy.models.firewallPolicy import *
from jammy.models.ipgroups import *


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def get_ip_addr_list(num):
    addr_list = []
    for i in range(0,num):
        ipaddr = '.'.join('%s'%random.randint(0, 255) for i in range(4))
        print(ipaddr)
        addr_list.append(ipaddr)
    return addr_list


class IpGroupUtil:

    def __init__(self, sub, loc, rg, cl):
        self._subscription_id = sub
        self._location = loc
        self._resource_group = rg
        self._cl = cl

    def get_resource_id(self, name):
        return '/subscriptions/' + self._subscription_id + '/resourceGroups/' + self._resource_group + \
               '/providers/Microsoft.Network/ipGroups/' + name

    def put(self, resource_id, ipg, tag=''):
        resourceJson = json.dumps(ipg.serialize())
        logger.info('tag%s:', tag)
        resp = self._cl.put_resource(resource_id, resourceJson, "2020-06-01", tag)
        return resp

    def get(self, resource_id):
        resp = self._cl.get_resource(resource_id, "2020-06-01")
        return IpGroup.from_dict(json.loads(resp))

    def create_ip_group(self, name, num_ips):
        logger.info("IPG create: %s", name)
        ipg = IpGroup()
        ipg.location = self._location
        ipg.resourceGroup = self._resource_group
        ipg.ip_addresses = get_ip_addr_list(num_ips)
        resource_id = self.get_resource_id(name)
        resp = self.put(resource_id, ipg)
        logger.info("IPG created: %s", resource_id)
        time.sleep(10)
        return resource_id

    def get_rule_with_ipg(self, rule_name):
        net_rule = NetworkRule()
        net_rule.name = rule_name
        sr = self.create_ip_group(rule_name+"ipgs", 2)
        dr = self.create_ip_group(rule_name+"ipgd", 2)
        net_rule.source_ip_groups = [sr]
        net_rule.destination_ip_groups = [dr]
        net_rule.destination_ports = [str(random.randint(0, 64000))]
        net_rule.ip_protocols = [FirewallPolicyRuleNetworkProtocol.udp]
        return net_rule

    def get_rule_list(self, name, num_rules):
        rule_list = []
        for i in range(0, num_rules):
            rule_list.append(self.get_rule_with_ipg(name + 'rule' + str(i)))
        return rule_list

    def get_ipg_resource_id(self, rcg_index, rc_index, rule_index, suffix_str):
        name = "RCG" + str(rcg_index) + "rl" + str(rc_index) + 'rule' + str(rule_index) + suffix_str
        resource_id = '/subscriptions/' + self._subscription_id + '/resourceGroups/' \
                      + self._resource_group + '/providers/Microsoft.Network/ipGroups/' + name
        return resource_id

    def update_ipg(self, resource_id, add_ips, del_ips, tag):
        try:
            logger.info("Update IP group: %s", resource_id)
            logger.info("IPs to add: %s", add_ips)
            logger.info("IPs to delete: %s", del_ips)
            ipg = self.get(resource_id)
            logger.info(" %s ips: %s", resource_id, ipg.ip_addresses)
            for ip in add_ips:
                # check if exists in ipg
                if ip not in ipg.ip_addresses:
                    ipg.ip_addresses.append(ip)
            for ip in del_ips:
                # check if exists in ipg
                if ip in ipg.ip_addresses:
                    ipg.ip_addresses.remove(ip)
            logger.info("%s updating to: %s", resource_id, ipg.ip_addresses)
            resp = self.put(resource_id, ipg, tag)
            ipg = self.get(resource_id)
            logger.info("GET IP Group %s: %s", resource_id, ipg)
            return ipg.provisioning_state
        except Exception as e:
            logger.info(e)
            return 'Failed'

    def get_ipg_tag(self, rcg_index, rc_index, rule_index, suffix_str):
        return "RCG" + str(rcg_index) + "rl" + str(rc_index) + 'rule' + str(rule_index) + suffix_str
