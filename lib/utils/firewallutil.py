"""
Utils for firewall policy Rule Collection Group
"""

import logging
import json

from jammy.models.azurefirewall import AzureFirewall
from jammy.models.azurefirewall import SubResource

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class FirewallUtil:

    def __init__(self, sub, loc, rg, cl):
        self._subscription_id = sub
        self._location = loc
        self._resourceGroup = rg
        self._cl = cl

    def get(self, resource_id):
        resp = self._cl.get_resource(resource_id, "2020-07-01")
        return AzureFirewall.from_dict(json.loads(resp))

    def put(self, resource_id, firewall):
        resourceJson = json.dumps(firewall.serialize())
        resp = self._cl.put_resource(resource_id, resourceJson, "2020-07-01")
        return resp

    def get_resource_id(self, fw_name):
        return '/subscriptions/' + self._subscription_id + '/resourceGroups/' + self._resourceGroup \
               + '/providers/Microsoft.Network/azureFirewalls/' + fw_name

    def associate_policy(self, firewall, policy_resource_id):
        policy_ref = SubResource()
        policy_ref.id = policy_resource_id
        firewall.firewall_policy = policy_ref
        resp = self.put(firewall.id, firewall)
