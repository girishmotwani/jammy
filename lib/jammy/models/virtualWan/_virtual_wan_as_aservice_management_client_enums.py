# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator (autorest: 3.0.6349, generator: {generator})
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from enum import Enum, EnumMeta
from six import with_metaclass

class _CaseInsensitiveEnumMeta(EnumMeta):
    def __getitem__(self, name):
        return super().__getitem__(name.upper())

    def __getattr__(cls, name):
        """Return the enum member matching `name`
        We use __getattr__ instead of descriptors or inserting into the enum
        class' __dict__ in order to support `name` and `value` being both
        properties for enum members (which live in the class' __dict__) and
        enum members themselves.
        """
        try:
            return cls._member_map_[name.upper()]
        except KeyError:
            raise AttributeError(name)


class AuthenticationMethod(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """VPN client authentication method.
    """

    EAPTLS = "EAPTLS"
    EAPMSCHA_PV2 = "EAPMSCHAPv2"

class DdosSettingsProtectionCoverage(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The DDoS protection policy customizability of the public IP. Only standard coverage will have
    the ability to be customized.
    """

    BASIC = "Basic"
    STANDARD = "Standard"

class DhGroup(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The DH Groups used in IKE Phase 1 for initial SA.
    """

    NONE = "None"
    DH_GROUP1 = "DHGroup1"
    DH_GROUP2 = "DHGroup2"
    DH_GROUP14 = "DHGroup14"
    DH_GROUP2048 = "DHGroup2048"
    ECP256 = "ECP256"
    ECP384 = "ECP384"
    DH_GROUP24 = "DHGroup24"

class ExtendedLocationTypes(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The supported ExtendedLocation types. Currently only EdgeZone is supported in Microsoft.Network
    resources.
    """

    EDGE_ZONE = "EdgeZone"

class FlowLogFormatType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The file type of flow log.
    """

    JSON = "JSON"

class HubBgpConnectionStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The current state of the VirtualHub to Peer.
    """

    UNKNOWN = "Unknown"
    CONNECTING = "Connecting"
    CONNECTED = "Connected"
    NOT_CONNECTED = "NotConnected"

class HubVirtualNetworkConnectionStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The current state of the VirtualHub to vnet connection.
    """

    UNKNOWN = "Unknown"
    CONNECTING = "Connecting"
    CONNECTED = "Connected"
    NOT_CONNECTED = "NotConnected"

class IkeEncryption(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The IKE encryption algorithm (IKE phase 2).
    """

    DES = "DES"
    DES3 = "DES3"
    AES128 = "AES128"
    AES192 = "AES192"
    AES256 = "AES256"
    GCMAES256 = "GCMAES256"
    GCMAES128 = "GCMAES128"

class IkeIntegrity(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The IKE integrity algorithm (IKE phase 2).
    """

    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    SHA384 = "SHA384"
    GCMAES256 = "GCMAES256"
    GCMAES128 = "GCMAES128"

class IPAllocationMethod(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """IP address allocation method.
    """

    STATIC = "Static"
    DYNAMIC = "Dynamic"

class IpsecEncryption(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The IPSec encryption algorithm (IKE phase 1).
    """

    NONE = "None"
    DES = "DES"
    DES3 = "DES3"
    AES128 = "AES128"
    AES192 = "AES192"
    AES256 = "AES256"
    GCMAES128 = "GCMAES128"
    GCMAES192 = "GCMAES192"
    GCMAES256 = "GCMAES256"

class IpsecIntegrity(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The IPSec integrity algorithm (IKE phase 1).
    """

    MD5 = "MD5"
    SHA1 = "SHA1"
    SHA256 = "SHA256"
    GCMAES128 = "GCMAES128"
    GCMAES192 = "GCMAES192"
    GCMAES256 = "GCMAES256"

class IPVersion(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """IP address version.
    """

    I_PV4 = "IPv4"
    I_PV6 = "IPv6"

class OfficeTrafficCategory(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The office traffic category.
    """

    OPTIMIZE = "Optimize"
    OPTIMIZE_AND_ALLOW = "OptimizeAndAllow"
    ALL = "All"
    NONE = "None"

class PfsGroup(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The Pfs Groups used in IKE Phase 2 for new child SA.
    """

    NONE = "None"
    PFS1 = "PFS1"
    PFS2 = "PFS2"
    PFS2048 = "PFS2048"
    ECP256 = "ECP256"
    ECP384 = "ECP384"
    PFS24 = "PFS24"
    PFS14 = "PFS14"
    PFSMM = "PFSMM"

class ProvisioningState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The current provisioning state.
    """

    SUCCEEDED = "Succeeded"
    UPDATING = "Updating"
    DELETING = "Deleting"
    FAILED = "Failed"

class PublicIPAddressSkuName(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Name of a public IP address SKU.
    """

    BASIC = "Basic"
    STANDARD = "Standard"

class PublicIPAddressSkuTier(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Tier of a public IP address SKU.
    """

    REGIONAL = "Regional"
    GLOBAL_ENUM = "Global"

class RouteNextHopType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of Azure hop the packet should be sent to.
    """

    VIRTUAL_NETWORK_GATEWAY = "VirtualNetworkGateway"
    VNET_LOCAL = "VnetLocal"
    INTERNET = "Internet"
    VIRTUAL_APPLIANCE = "VirtualAppliance"
    NONE = "None"

class RoutingState(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The current routing state of the VirtualHub.
    """

    NONE = "None"
    PROVISIONED = "Provisioned"
    PROVISIONING = "Provisioning"
    FAILED = "Failed"

class SecurityRuleAccess(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Whether network traffic is allowed or denied.
    """

    ALLOW = "Allow"
    DENY = "Deny"

class SecurityRuleDirection(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The direction of the rule. The direction specifies if rule will be evaluated on incoming or
    outgoing traffic.
    """

    INBOUND = "Inbound"
    OUTBOUND = "Outbound"

class SecurityRuleProtocol(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Network protocol this rule applies to.
    """

    TCP = "Tcp"
    UDP = "Udp"
    ICMP = "Icmp"
    ESP = "Esp"
    ASTERISK = "*"
    AH = "Ah"

class TransportProtocol(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The transport protocol for the endpoint.
    """

    UDP = "Udp"
    TCP = "Tcp"
    ALL = "All"

class TunnelConnectionStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The current state of the tunnel.
    """

    UNKNOWN = "Unknown"
    CONNECTING = "Connecting"
    CONNECTED = "Connected"
    NOT_CONNECTED = "NotConnected"

class VirtualNetworkGatewayConnectionProtocol(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Gateway connection protocol.
    """

    IK_EV2 = "IKEv2"
    IK_EV1 = "IKEv1"

class VirtualWanSecurityProviderType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The virtual wan security provider type.
    """

    EXTERNAL = "External"
    NATIVE = "Native"

class VpnAuthenticationType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """VPN authentication types enabled for the VpnServerConfiguration.
    """

    CERTIFICATE = "Certificate"
    RADIUS = "Radius"
    AAD = "AAD"

class VpnConnectionStatus(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The current state of the vpn connection.
    """

    UNKNOWN = "Unknown"
    CONNECTING = "Connecting"
    CONNECTED = "Connected"
    NOT_CONNECTED = "NotConnected"

class VpnGatewayTunnelingProtocol(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """VPN protocol enabled for the VpnServerConfiguration.
    """

    IKE_V2 = "IkeV2"
    OPEN_VPN = "OpenVPN"

class VpnLinkConnectionMode(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """Vpn link connection mode.
    """

    DEFAULT = "Default"
    RESPONDER_ONLY = "ResponderOnly"
    INITIATOR_ONLY = "InitiatorOnly"

class VpnNatRuleMode(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The Source NAT direction of a VPN NAT.
    """

    EGRESS_SNAT = "EgressSnat"
    INGRESS_SNAT = "IngressSnat"

class VpnNatRuleType(with_metaclass(_CaseInsensitiveEnumMeta, str, Enum)):
    """The type of NAT rule for VPN NAT.
    """

    STATIC = "Static"
    DYNAMIC = "Dynamic"
