#!/usr/bin/python

import argparse
from jammy.armclient import ArmClient

## Usage
# python3 deployTemplate.py --resourceGroup test04RG --subscriptionId f6cb8187-b300-4c2d-9b23-c00e7e98d799 --filePath ../tests/firewall_policy/templates/firewallPolicySandbox.json
###

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--location', required=False, default= "eastus",
	help='Region where the resource template should be deployed')
    parser.add_argument('--resourceGroup', required=True,
	help='Resource Group Name')
    parser.add_argument('--subscriptionId', required=True,
	help='Subscription Id')
    parser.add_argument('--filePath', required=True,
	help='Path of the template file')
    args = parser.parse_args()
    cl = ArmClient()

    rg = cl.create_resource_group(args.subscriptionId, args.resourceGroup, args.location)
    resource_group_id = '/subscriptions/' + args.subscriptionId + '/resourceGroups/' + args.resourceGroup 
    cl.deploy_template(args.subscriptionId, "test-deployment", args.resourceGroup, args.location, args.filePath)

if __name__ == '__main__':
    main()
