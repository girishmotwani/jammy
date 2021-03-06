# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from enum import Enum


class ProvisioningState(str, Enum):

    succeeded = "Succeeded"
    updating = "Updating"
    deleting = "Deleting"
    failed = "Failed"


class AzureFirewallRCActionType(str, Enum):

    allow = "Allow"
    deny = "Deny"


class AzureFirewallApplicationRuleProtocolType(str, Enum):

    http = "Http"
    https = "Https"
    mssql = "Mssql"


class AzureFirewallNatRCActionType(str, Enum):

    snat = "Snat"
    dnat = "Dnat"


class AzureFirewallNetworkRuleProtocol(str, Enum):

    tcp = "TCP"
    udp = "UDP"
    any = "Any"
    icmp = "ICMP"


class AzureFirewallThreatIntelMode(str, Enum):

    alert = "Alert"
    deny = "Deny"
    off = "Off"


class AzureFirewallSkuName(str, Enum):

    azfw_vnet = "AZFW_VNet"
    azfw_hub = "AZFW_Hub"


class AzureFirewallSkuTier(str, Enum):

    standard = "Standard"
    premium = "Premium"
