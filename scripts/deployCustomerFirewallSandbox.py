#!/usr/bin/python

import json
import os
import argparse
from jammy.armclient import ArmClient
from jammy.models.ipgroups import *
from jammy.models.firewallPolicy import *
from jammy.models.firewallPolicy import version

from jammy.models.azurefirewall import AzureFirewall
## Usage
# python3 deployCustomerFirewallSandbox.py --resourceGroup test04RG --subscriptionId f6cb8187-b300-4c2d-9b23-c00e7e98d799 --policyPath ../tests/firewall_policy/jsons/firewallPolicy01.json
###

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--location', required=False, default= "eastus",
	help='Region where the resource template should be deployed')
    parser.add_argument('--resourceGroup', required=True,
	help='Resource Group Name')
    parser.add_argument('--subscriptionId', required=True,
	help='Subscription Id')
    parser.add_argument('--policyPath', required=True,
	help='Path of the customer firewall policy json file')
    parser.add_argument('--subscriptionIds', required=True,
	help='Subscription Ids', nargs='*')
    args = parser.parse_args()
    cl = ArmClient()

    # path to vnet sandbox 
    template_path = '../tests/firewall_policy/templates/firewallPolicySandbox.json'

    rg = cl.create_resource_group(args.subscriptionId, args.resourceGroup, args.location)
    resource_group_id = '/subscriptions/' + args.subscriptionId + '/resourceGroups/' + args.resourceGroup 
    cl.deploy_template(args.subscriptionId, "test-deployment01", args.resourceGroup, args.location, template_path)

    # load the firewall policy from json
    fw_policy_resource_id =resource_group_id + '/providers/Microsoft.Network/firewallPolicies/' + 'fwpolicy01'
    rcg_list = []
    for filename in os.listdir(args.policyPath):
        if filename.endswith('.json'):
            print('Opening file ', filename)
            with open(os.path.join(args.policyPath, filename), 'r') as f:
                resource_dict = json.load(f)
                if "RuleCollectionGroups" in resource_dict['type']:
                    rcg = FirewallPolicyRuleCollectionGroup.from_dict(resource_dict)
                    rcg.id = None
                    rcg.location = args.location
                    rcg_list.append(rcg)
                else if "IpGroups" in resource_dict['type']:
                    ip_group = IpGroup.from_dict(resource_dict) 
                    ip_group.id = None
                    ip_group.location = args.location

                    ip_group_resource_id = resource_group_id + '/providers/Microsoft.Network/ipgroups/' + resource_dict['name']
                    print('Creating Resource: ', ip_group_resource_id)
                    resp = cl.put_resource(ip_group_resource_id, json.dumps(ip_group.serialize()), "2020-08-01")

                else:
                    fp = FirewallPolicy.from_dict(resource_dict)
                    fp.location = args.location
                    fp.resourceGroup = args.resourceGroup
                    fp.id = None

                    # create the firewall policy resource
                    resp = cl.put_resource(fw_policy_resource_id, json.dumps(fp.serialize()), "2020-06-01")

    for index, rcg in enumerate(rcg_list):
        res_id = fw_policy_resource_id + '/RuleCollectionGroups/rcg' + str(index)
        print('Creating Resource: ', res_id)
        resp = cl.put_resource(res_id, json.dumps(rcg.serialize()), "2020-06-01")
        print('Created Resource: ', res_id)

if __name__ == '__main__':
    main()
