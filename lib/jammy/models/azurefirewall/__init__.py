# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator (autorest: 3.0.6349, generator: {generator})
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import AzureFirewall
    from ._models_py3 import AzureFirewallApplicationRule
    from ._models_py3 import AzureFirewallApplicationRuleCollection
    from ._models_py3 import AzureFirewallApplicationRuleProtocol
    from ._models_py3 import AzureFirewallIPConfiguration
    from ._models_py3 import AzureFirewallIpGroups
    from ._models_py3 import AzureFirewallListResult
    from ._models_py3 import AzureFirewallNatRCAction
    from ._models_py3 import AzureFirewallNatRule
    from ._models_py3 import AzureFirewallNatRuleCollection
    from ._models_py3 import AzureFirewallNetworkRule
    from ._models_py3 import AzureFirewallNetworkRuleCollection
    from ._models_py3 import AzureFirewallPublicIPAddress
    from ._models_py3 import AzureFirewallRCAction
    from ._models_py3 import AzureFirewallSku
    from ._models_py3 import CloudError
    from ._models_py3 import CloudErrorBody
    from ._models_py3 import HubIPAddresses
    from ._models_py3 import HubPublicIPAddresses
    from ._models_py3 import Resource
    from ._models_py3 import SubResource
    from ._models_py3 import TagsObject
except (SyntaxError, ImportError):
    from ._models import AzureFirewall  # type: ignore
    from ._models import AzureFirewallApplicationRule  # type: ignore
    from ._models import AzureFirewallApplicationRuleCollection  # type: ignore
    from ._models import AzureFirewallApplicationRuleProtocol  # type: ignore
    from ._models import AzureFirewallIPConfiguration  # type: ignore
    from ._models import AzureFirewallIpGroups  # type: ignore
    from ._models import AzureFirewallListResult  # type: ignore
    from ._models import AzureFirewallNatRCAction  # type: ignore
    from ._models import AzureFirewallNatRule  # type: ignore
    from ._models import AzureFirewallNatRuleCollection  # type: ignore
    from ._models import AzureFirewallNetworkRule  # type: ignore
    from ._models import AzureFirewallNetworkRuleCollection  # type: ignore
    from ._models import AzureFirewallPublicIPAddress  # type: ignore
    from ._models import AzureFirewallRCAction  # type: ignore
    from ._models import AzureFirewallSku  # type: ignore
    from ._models import CloudError  # type: ignore
    from ._models import CloudErrorBody  # type: ignore
    from ._models import HubIPAddresses  # type: ignore
    from ._models import HubPublicIPAddresses  # type: ignore
    from ._models import Resource  # type: ignore
    from ._models import SubResource  # type: ignore
    from ._models import TagsObject  # type: ignore

from ._network_management_client_enums import (
    AzureFirewallApplicationRuleProtocolType,
    AzureFirewallNatRCActionType,
    AzureFirewallNetworkRuleProtocol,
    AzureFirewallRCActionType,
    AzureFirewallSkuName,
    AzureFirewallSkuTier,
    AzureFirewallThreatIntelMode,
    ProvisioningState,
)

__all__ = [
    'AzureFirewall',
    'AzureFirewallApplicationRule',
    'AzureFirewallApplicationRuleCollection',
    'AzureFirewallApplicationRuleProtocol',
    'AzureFirewallIPConfiguration',
    'AzureFirewallIpGroups',
    'AzureFirewallListResult',
    'AzureFirewallNatRCAction',
    'AzureFirewallNatRule',
    'AzureFirewallNatRuleCollection',
    'AzureFirewallNetworkRule',
    'AzureFirewallNetworkRuleCollection',
    'AzureFirewallPublicIPAddress',
    'AzureFirewallRCAction',
    'AzureFirewallSku',
    'CloudError',
    'CloudErrorBody',
    'HubIPAddresses',
    'HubPublicIPAddresses',
    'Resource',
    'SubResource',
    'TagsObject',
    'AzureFirewallApplicationRuleProtocolType',
    'AzureFirewallNatRCActionType',
    'AzureFirewallNetworkRuleProtocol',
    'AzureFirewallRCActionType',
    'AzureFirewallSkuName',
    'AzureFirewallSkuTier',
    'AzureFirewallThreatIntelMode',
    'ProvisioningState',
]
