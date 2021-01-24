# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator (autorest: 3.0.6349, generator: {generator})
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import AadAuthenticationParameters
    from ._models_py3 import AddressSpace
    from ._models_py3 import ApplicationGatewayBackendAddress
    from ._models_py3 import ApplicationGatewayBackendAddressPool
    from ._models_py3 import ApplicationSecurityGroup
    from ._models_py3 import BackendAddressPool
    from ._models_py3 import BgpConnection
    from ._models_py3 import BgpSettings
    from ._models_py3 import CloudError
    from ._models_py3 import CloudErrorBody
    from ._models_py3 import CustomDnsConfigPropertiesFormat
    from ._models_py3 import DdosSettings
    from ._models_py3 import Delegation
    from ._models_py3 import DeviceProperties
    from ._models_py3 import EffectiveRoutesParameters
    from ._models_py3 import Error
    from ._models_py3 import ErrorDetails
    from ._models_py3 import ExpressRouteCircuitPeeringId
    from ._models_py3 import ExpressRouteConnection
    from ._models_py3 import ExpressRouteConnectionId
    from ._models_py3 import ExpressRouteConnectionList
    from ._models_py3 import ExpressRouteGateway
    from ._models_py3 import ExpressRouteGatewayList
    from ._models_py3 import ExpressRouteGatewayPropertiesAutoScaleConfiguration
    from ._models_py3 import ExpressRouteGatewayPropertiesAutoScaleConfigurationBounds
    from ._models_py3 import ExtendedLocation
    from ._models_py3 import FlowLog
    from ._models_py3 import FlowLogFormatParameters
    from ._models_py3 import FrontendIPConfiguration
    from ._models_py3 import GetVpnSitesConfigurationRequest
    from ._models_py3 import HubIpConfiguration
    from ._models_py3 import HubRoute
    from ._models_py3 import HubRouteTable
    from ._models_py3 import HubVirtualNetworkConnection
    from ._models_py3 import IPConfiguration
    from ._models_py3 import IPConfigurationBgpPeeringAddress
    from ._models_py3 import IPConfigurationProfile
    from ._models_py3 import InboundNatRule
    from ._models_py3 import IpTag
    from ._models_py3 import IpsecPolicy
    from ._models_py3 import ListHubRouteTablesResult
    from ._models_py3 import ListHubVirtualNetworkConnectionsResult
    from ._models_py3 import ListP2SVpnGatewaysResult
    from ._models_py3 import ListVirtualHubBgpConnectionResults
    from ._models_py3 import ListVirtualHubIpConfigurationResults
    from ._models_py3 import ListVirtualHubRouteTableV2SResult
    from ._models_py3 import ListVirtualHubsResult
    from ._models_py3 import ListVirtualWANsResult
    from ._models_py3 import ListVpnConnectionsResult
    from ._models_py3 import ListVpnGatewayNatRulesResult
    from ._models_py3 import ListVpnGatewaysResult
    from ._models_py3 import ListVpnServerConfigurationsResult
    from ._models_py3 import ListVpnSiteLinkConnectionsResult
    from ._models_py3 import ListVpnSiteLinksResult
    from ._models_py3 import ListVpnSitesResult
    from ._models_py3 import LoadBalancerBackendAddress
    from ._models_py3 import NetworkInterface
    from ._models_py3 import NetworkInterfaceDnsSettings
    from ._models_py3 import NetworkInterfaceIPConfiguration
    from ._models_py3 import NetworkInterfaceIPConfigurationPrivateLinkConnectionProperties
    from ._models_py3 import NetworkInterfaceTapConfiguration
    from ._models_py3 import NetworkSecurityGroup
    from ._models_py3 import O365BreakOutCategoryPolicies
    from ._models_py3 import O365PolicyProperties
    from ._models_py3 import P2SConnectionConfiguration
    from ._models_py3 import P2SVpnConnectionHealth
    from ._models_py3 import P2SVpnConnectionHealthRequest
    from ._models_py3 import P2SVpnConnectionRequest
    from ._models_py3 import P2SVpnGateway
    from ._models_py3 import P2SVpnProfileParameters
    from ._models_py3 import PeerRoute
    from ._models_py3 import PeerRouteList
    from ._models_py3 import PrivateEndpoint
    from ._models_py3 import PrivateLinkServiceConnection
    from ._models_py3 import PrivateLinkServiceConnectionState
    from ._models_py3 import PropagatedRouteTable
    from ._models_py3 import PublicIPAddress
    from ._models_py3 import PublicIPAddressDnsSettings
    from ._models_py3 import PublicIPAddressSku
    from ._models_py3 import RadiusServer
    from ._models_py3 import Resource
    from ._models_py3 import ResourceNavigationLink
    from ._models_py3 import RetentionPolicyParameters
    from ._models_py3 import Route
    from ._models_py3 import RouteTable
    from ._models_py3 import RoutingConfiguration
    from ._models_py3 import SecurityRule
    from ._models_py3 import ServiceAssociationLink
    from ._models_py3 import ServiceEndpointPolicy
    from ._models_py3 import ServiceEndpointPolicyDefinition
    from ._models_py3 import ServiceEndpointPropertiesFormat
    from ._models_py3 import StaticRoute
    from ._models_py3 import SubResource
    from ._models_py3 import Subnet
    from ._models_py3 import TagsObject
    from ._models_py3 import TrafficAnalyticsConfigurationProperties
    from ._models_py3 import TrafficAnalyticsProperties
    from ._models_py3 import VirtualHub
    from ._models_py3 import VirtualHubEffectiveRoute
    from ._models_py3 import VirtualHubEffectiveRouteList
    from ._models_py3 import VirtualHubId
    from ._models_py3 import VirtualHubRoute
    from ._models_py3 import VirtualHubRouteTable
    from ._models_py3 import VirtualHubRouteTableV2
    from ._models_py3 import VirtualHubRouteV2
    from ._models_py3 import VirtualNetworkTap
    from ._models_py3 import VirtualWAN
    from ._models_py3 import VirtualWanSecurityProvider
    from ._models_py3 import VirtualWanSecurityProviders
    from ._models_py3 import VirtualWanVpnProfileParameters
    from ._models_py3 import VnetRoute
    from ._models_py3 import VpnClientConnectionHealth
    from ._models_py3 import VpnConnection
    from ._models_py3 import VpnConnectionPacketCaptureStartParameters
    from ._models_py3 import VpnConnectionPacketCaptureStopParameters
    from ._models_py3 import VpnGateway
    from ._models_py3 import VpnGatewayIpConfiguration
    from ._models_py3 import VpnGatewayNatRule
    from ._models_py3 import VpnGatewayPacketCaptureStartParameters
    from ._models_py3 import VpnGatewayPacketCaptureStopParameters
    from ._models_py3 import VpnLinkBgpSettings
    from ._models_py3 import VpnLinkProviderProperties
    from ._models_py3 import VpnNatRuleMapping
    from ._models_py3 import VpnProfileResponse
    from ._models_py3 import VpnServerConfigRadiusClientRootCertificate
    from ._models_py3 import VpnServerConfigRadiusServerRootCertificate
    from ._models_py3 import VpnServerConfigVpnClientRevokedCertificate
    from ._models_py3 import VpnServerConfigVpnClientRootCertificate
    from ._models_py3 import VpnServerConfiguration
    from ._models_py3 import VpnServerConfigurationsResponse
    from ._models_py3 import VpnSite
    from ._models_py3 import VpnSiteId
    from ._models_py3 import VpnSiteLink
    from ._models_py3 import VpnSiteLinkConnection
    from .version import VERSION
except (SyntaxError, ImportError):
    from ._models import AadAuthenticationParameters  # type: ignore
    from ._models import AddressSpace  # type: ignore
    from ._models import ApplicationGatewayBackendAddress  # type: ignore
    from ._models import ApplicationGatewayBackendAddressPool  # type: ignore
    from ._models import ApplicationSecurityGroup  # type: ignore
    from ._models import BackendAddressPool  # type: ignore
    from ._models import BgpConnection  # type: ignore
    from ._models import BgpSettings  # type: ignore
    from ._models import CloudError  # type: ignore
    from ._models import CloudErrorBody  # type: ignore
    from ._models import CustomDnsConfigPropertiesFormat  # type: ignore
    from ._models import DdosSettings  # type: ignore
    from ._models import Delegation  # type: ignore
    from ._models import DeviceProperties  # type: ignore
    from ._models import EffectiveRoutesParameters  # type: ignore
    from ._models import Error  # type: ignore
    from ._models import ErrorDetails  # type: ignore
    from ._models import ExpressRouteCircuitPeeringId  # type: ignore
    from ._models import ExpressRouteConnection  # type: ignore
    from ._models import ExpressRouteConnectionId  # type: ignore
    from ._models import ExpressRouteConnectionList  # type: ignore
    from ._models import ExpressRouteGateway  # type: ignore
    from ._models import ExpressRouteGatewayList  # type: ignore
    from ._models import ExpressRouteGatewayPropertiesAutoScaleConfiguration  # type: ignore
    from ._models import ExpressRouteGatewayPropertiesAutoScaleConfigurationBounds  # type: ignore
    from ._models import ExtendedLocation  # type: ignore
    from ._models import FlowLog  # type: ignore
    from ._models import FlowLogFormatParameters  # type: ignore
    from ._models import FrontendIPConfiguration  # type: ignore
    from ._models import GetVpnSitesConfigurationRequest  # type: ignore
    from ._models import HubIpConfiguration  # type: ignore
    from ._models import HubRoute  # type: ignore
    from ._models import HubRouteTable  # type: ignore
    from ._models import HubVirtualNetworkConnection  # type: ignore
    from ._models import IPConfiguration  # type: ignore
    from ._models import IPConfigurationBgpPeeringAddress  # type: ignore
    from ._models import IPConfigurationProfile  # type: ignore
    from ._models import InboundNatRule  # type: ignore
    from ._models import IpTag  # type: ignore
    from ._models import IpsecPolicy  # type: ignore
    from ._models import ListHubRouteTablesResult  # type: ignore
    from ._models import ListHubVirtualNetworkConnectionsResult  # type: ignore
    from ._models import ListP2SVpnGatewaysResult  # type: ignore
    from ._models import ListVirtualHubBgpConnectionResults  # type: ignore
    from ._models import ListVirtualHubIpConfigurationResults  # type: ignore
    from ._models import ListVirtualHubRouteTableV2SResult  # type: ignore
    from ._models import ListVirtualHubsResult  # type: ignore
    from ._models import ListVirtualWANsResult  # type: ignore
    from ._models import ListVpnConnectionsResult  # type: ignore
    from ._models import ListVpnGatewayNatRulesResult  # type: ignore
    from ._models import ListVpnGatewaysResult  # type: ignore
    from ._models import ListVpnServerConfigurationsResult  # type: ignore
    from ._models import ListVpnSiteLinkConnectionsResult  # type: ignore
    from ._models import ListVpnSiteLinksResult  # type: ignore
    from ._models import ListVpnSitesResult  # type: ignore
    from ._models import LoadBalancerBackendAddress  # type: ignore
    from ._models import NetworkInterface  # type: ignore
    from ._models import NetworkInterfaceDnsSettings  # type: ignore
    from ._models import NetworkInterfaceIPConfiguration  # type: ignore
    from ._models import NetworkInterfaceIPConfigurationPrivateLinkConnectionProperties  # type: ignore
    from ._models import NetworkInterfaceTapConfiguration  # type: ignore
    from ._models import NetworkSecurityGroup  # type: ignore
    from ._models import O365BreakOutCategoryPolicies  # type: ignore
    from ._models import O365PolicyProperties  # type: ignore
    from ._models import P2SConnectionConfiguration  # type: ignore
    from ._models import P2SVpnConnectionHealth  # type: ignore
    from ._models import P2SVpnConnectionHealthRequest  # type: ignore
    from ._models import P2SVpnConnectionRequest  # type: ignore
    from ._models import P2SVpnGateway  # type: ignore
    from ._models import P2SVpnProfileParameters  # type: ignore
    from ._models import PeerRoute  # type: ignore
    from ._models import PeerRouteList  # type: ignore
    from ._models import PrivateEndpoint  # type: ignore
    from ._models import PrivateLinkServiceConnection  # type: ignore
    from ._models import PrivateLinkServiceConnectionState  # type: ignore
    from ._models import PropagatedRouteTable  # type: ignore
    from ._models import PublicIPAddress  # type: ignore
    from ._models import PublicIPAddressDnsSettings  # type: ignore
    from ._models import PublicIPAddressSku  # type: ignore
    from ._models import RadiusServer  # type: ignore
    from ._models import Resource  # type: ignore
    from ._models import ResourceNavigationLink  # type: ignore
    from ._models import RetentionPolicyParameters  # type: ignore
    from ._models import Route  # type: ignore
    from ._models import RouteTable  # type: ignore
    from ._models import RoutingConfiguration  # type: ignore
    from ._models import SecurityRule  # type: ignore
    from ._models import ServiceAssociationLink  # type: ignore
    from ._models import ServiceEndpointPolicy  # type: ignore
    from ._models import ServiceEndpointPolicyDefinition  # type: ignore
    from ._models import ServiceEndpointPropertiesFormat  # type: ignore
    from ._models import StaticRoute  # type: ignore
    from ._models import SubResource  # type: ignore
    from ._models import Subnet  # type: ignore
    from ._models import TagsObject  # type: ignore
    from ._models import TrafficAnalyticsConfigurationProperties  # type: ignore
    from ._models import TrafficAnalyticsProperties  # type: ignore
    from ._models import VirtualHub  # type: ignore
    from ._models import VirtualHubEffectiveRoute  # type: ignore
    from ._models import VirtualHubEffectiveRouteList  # type: ignore
    from ._models import VirtualHubId  # type: ignore
    from ._models import VirtualHubRoute  # type: ignore
    from ._models import VirtualHubRouteTable  # type: ignore
    from ._models import VirtualHubRouteTableV2  # type: ignore
    from ._models import VirtualHubRouteV2  # type: ignore
    from ._models import VirtualNetworkTap  # type: ignore
    from ._models import VirtualWAN  # type: ignore
    from ._models import VirtualWanSecurityProvider  # type: ignore
    from ._models import VirtualWanSecurityProviders  # type: ignore
    from ._models import VirtualWanVpnProfileParameters  # type: ignore
    from ._models import VnetRoute  # type: ignore
    from ._models import VpnClientConnectionHealth  # type: ignore
    from ._models import VpnConnection  # type: ignore
    from ._models import VpnConnectionPacketCaptureStartParameters  # type: ignore
    from ._models import VpnConnectionPacketCaptureStopParameters  # type: ignore
    from ._models import VpnGateway  # type: ignore
    from ._models import VpnGatewayIpConfiguration  # type: ignore
    from ._models import VpnGatewayNatRule  # type: ignore
    from ._models import VpnGatewayPacketCaptureStartParameters  # type: ignore
    from ._models import VpnGatewayPacketCaptureStopParameters  # type: ignore
    from ._models import VpnLinkBgpSettings  # type: ignore
    from ._models import VpnLinkProviderProperties  # type: ignore
    from ._models import VpnNatRuleMapping  # type: ignore
    from ._models import VpnProfileResponse  # type: ignore
    from ._models import VpnServerConfigRadiusClientRootCertificate  # type: ignore
    from ._models import VpnServerConfigRadiusServerRootCertificate  # type: ignore
    from ._models import VpnServerConfigVpnClientRevokedCertificate  # type: ignore
    from ._models import VpnServerConfigVpnClientRootCertificate  # type: ignore
    from ._models import VpnServerConfiguration  # type: ignore
    from ._models import VpnServerConfigurationsResponse  # type: ignore
    from ._models import VpnSite  # type: ignore
    from ._models import VpnSiteId  # type: ignore
    from ._models import VpnSiteLink  # type: ignore
    from ._models import VpnSiteLinkConnection  # type: ignore
    from .version import VERSION

from ._virtual_wan_as_aservice_management_client_enums import (
    AuthenticationMethod,
    DdosSettingsProtectionCoverage,
    DhGroup,
    ExtendedLocationTypes,
    FlowLogFormatType,
    HubBgpConnectionStatus,
    HubVirtualNetworkConnectionStatus,
    IPAllocationMethod,
    IPVersion,
    IkeEncryption,
    IkeIntegrity,
    IpsecEncryption,
    IpsecIntegrity,
    OfficeTrafficCategory,
    PfsGroup,
    ProvisioningState,
    PublicIPAddressSkuName,
    PublicIPAddressSkuTier,
    RouteNextHopType,
    RoutingState,
    SecurityRuleAccess,
    SecurityRuleDirection,
    SecurityRuleProtocol,
    TransportProtocol,
    TunnelConnectionStatus,
    VirtualNetworkGatewayConnectionProtocol,
    VirtualWanSecurityProviderType,
    VpnAuthenticationType,
    VpnConnectionStatus,
    VpnGatewayTunnelingProtocol,
    VpnLinkConnectionMode,
    VpnNatRuleMode,
    VpnNatRuleType,
)

__all__ = [
    'AadAuthenticationParameters',
    'AddressSpace',
    'ApplicationGatewayBackendAddress',
    'ApplicationGatewayBackendAddressPool',
    'ApplicationSecurityGroup',
    'BackendAddressPool',
    'BgpConnection',
    'BgpSettings',
    'CloudError',
    'CloudErrorBody',
    'CustomDnsConfigPropertiesFormat',
    'DdosSettings',
    'Delegation',
    'DeviceProperties',
    'EffectiveRoutesParameters',
    'Error',
    'ErrorDetails',
    'ExpressRouteCircuitPeeringId',
    'ExpressRouteConnection',
    'ExpressRouteConnectionId',
    'ExpressRouteConnectionList',
    'ExpressRouteGateway',
    'ExpressRouteGatewayList',
    'ExpressRouteGatewayPropertiesAutoScaleConfiguration',
    'ExpressRouteGatewayPropertiesAutoScaleConfigurationBounds',
    'ExtendedLocation',
    'FlowLog',
    'FlowLogFormatParameters',
    'FrontendIPConfiguration',
    'GetVpnSitesConfigurationRequest',
    'HubIpConfiguration',
    'HubRoute',
    'HubRouteTable',
    'HubVirtualNetworkConnection',
    'IPConfiguration',
    'IPConfigurationBgpPeeringAddress',
    'IPConfigurationProfile',
    'InboundNatRule',
    'IpTag',
    'IpsecPolicy',
    'ListHubRouteTablesResult',
    'ListHubVirtualNetworkConnectionsResult',
    'ListP2SVpnGatewaysResult',
    'ListVirtualHubBgpConnectionResults',
    'ListVirtualHubIpConfigurationResults',
    'ListVirtualHubRouteTableV2SResult',
    'ListVirtualHubsResult',
    'ListVirtualWANsResult',
    'ListVpnConnectionsResult',
    'ListVpnGatewayNatRulesResult',
    'ListVpnGatewaysResult',
    'ListVpnServerConfigurationsResult',
    'ListVpnSiteLinkConnectionsResult',
    'ListVpnSiteLinksResult',
    'ListVpnSitesResult',
    'LoadBalancerBackendAddress',
    'NetworkInterface',
    'NetworkInterfaceDnsSettings',
    'NetworkInterfaceIPConfiguration',
    'NetworkInterfaceIPConfigurationPrivateLinkConnectionProperties',
    'NetworkInterfaceTapConfiguration',
    'NetworkSecurityGroup',
    'O365BreakOutCategoryPolicies',
    'O365PolicyProperties',
    'P2SConnectionConfiguration',
    'P2SVpnConnectionHealth',
    'P2SVpnConnectionHealthRequest',
    'P2SVpnConnectionRequest',
    'P2SVpnGateway',
    'P2SVpnProfileParameters',
    'PeerRoute',
    'PeerRouteList',
    'PrivateEndpoint',
    'PrivateLinkServiceConnection',
    'PrivateLinkServiceConnectionState',
    'PropagatedRouteTable',
    'PublicIPAddress',
    'PublicIPAddressDnsSettings',
    'PublicIPAddressSku',
    'RadiusServer',
    'Resource',
    'ResourceNavigationLink',
    'RetentionPolicyParameters',
    'Route',
    'RouteTable',
    'RoutingConfiguration',
    'SecurityRule',
    'ServiceAssociationLink',
    'ServiceEndpointPolicy',
    'ServiceEndpointPolicyDefinition',
    'ServiceEndpointPropertiesFormat',
    'StaticRoute',
    'SubResource',
    'Subnet',
    'TagsObject',
    'TrafficAnalyticsConfigurationProperties',
    'TrafficAnalyticsProperties',
    'VirtualHub',
    'VirtualHubEffectiveRoute',
    'VirtualHubEffectiveRouteList',
    'VirtualHubId',
    'VirtualHubRoute',
    'VirtualHubRouteTable',
    'VirtualHubRouteTableV2',
    'VirtualHubRouteV2',
    'VirtualNetworkTap',
    'VirtualWAN',
    'VirtualWanSecurityProvider',
    'VirtualWanSecurityProviders',
    'VirtualWanVpnProfileParameters',
    'VnetRoute',
    'VpnClientConnectionHealth',
    'VpnConnection',
    'VpnConnectionPacketCaptureStartParameters',
    'VpnConnectionPacketCaptureStopParameters',
    'VpnGateway',
    'VpnGatewayIpConfiguration',
    'VpnGatewayNatRule',
    'VpnGatewayPacketCaptureStartParameters',
    'VpnGatewayPacketCaptureStopParameters',
    'VpnLinkBgpSettings',
    'VpnLinkProviderProperties',
    'VpnNatRuleMapping',
    'VpnProfileResponse',
    'VpnServerConfigRadiusClientRootCertificate',
    'VpnServerConfigRadiusServerRootCertificate',
    'VpnServerConfigVpnClientRevokedCertificate',
    'VpnServerConfigVpnClientRootCertificate',
    'VpnServerConfiguration',
    'VpnServerConfigurationsResponse',
    'VpnSite',
    'VpnSiteId',
    'VpnSiteLink',
    'VpnSiteLinkConnection',
    'AuthenticationMethod',
    'DdosSettingsProtectionCoverage',
    'DhGroup',
    'ExtendedLocationTypes',
    'FlowLogFormatType',
    'HubBgpConnectionStatus',
    'HubVirtualNetworkConnectionStatus',
    'IPAllocationMethod',
    'IPVersion',
    'IkeEncryption',
    'IkeIntegrity',
    'IpsecEncryption',
    'IpsecIntegrity',
    'OfficeTrafficCategory',
    'PfsGroup',
    'ProvisioningState',
    'PublicIPAddressSkuName',
    'PublicIPAddressSkuTier',
    'RouteNextHopType',
    'RoutingState',
    'SecurityRuleAccess',
    'SecurityRuleDirection',
    'SecurityRuleProtocol',
    'TransportProtocol',
    'TunnelConnectionStatus',
    'VirtualNetworkGatewayConnectionProtocol',
    'VirtualWanSecurityProviderType',
    'VpnAuthenticationType',
    'VpnConnectionStatus',
    'VpnGatewayTunnelingProtocol',
    'VpnLinkConnectionMode',
    'VpnNatRuleMode',
    'VpnNatRuleType',
]