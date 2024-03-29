# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator (autorest: 3.0.6349, generator: {generator})
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import Dict, List, Optional, Union

from azure.core.exceptions import HttpResponseError
import msrest.serialization

from ._network_management_client_enums import *

class SubResource(msrest.serialization.Model):
    """Reference to another subresource.

    :ivar id: Resource ID.
    :vartype id: str
    """

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        id: Optional[str] = None,
        **kwargs
    ):
        """
        :keyword id: Resource ID.
        :paramtype id: str
        """
        super(SubResource, self).__init__(**kwargs)
        self.id = id

class Resource(msrest.serialization.Model):
    """Common resource representation.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :ivar location: Resource location.
    :vartype location: str
    :ivar tags: A set of tags. Resource tags.
    :vartype tags: dict[str, str]
    """

    _validation = {
        'name': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(
        self,
        *,
        id: Optional[str] = None,
        location: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None,
        **kwargs
    ):
        """
        :keyword id: Resource ID.
        :paramtype id: str
        :keyword location: Resource location.
        :paramtype location: str
        :keyword tags: A set of tags. Resource tags.
        :paramtype tags: dict[str, str]
        """
        super(Resource, self).__init__(**kwargs)
        self.id = id
        self.name = None
        self.type = None
        self.location = location
 

class PublicIPAddress(Resource):
    """Public IP address resource.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :ivar location: Resource location.
    :vartype location: str
    :ivar tags: A set of tags. Resource tags.
    :vartype tags: dict[str, str]
    :ivar extended_location: The extended location of the public ip address.
    :vartype extended_location: ~azure.mgmt.network.v2022_01_01.models.ExtendedLocation
    :ivar sku: The public IP address SKU.
    :vartype sku: ~azure.mgmt.network.v2022_01_01.models.PublicIPAddressSku
    :ivar etag: A unique read-only string that changes whenever the resource is updated.
    :vartype etag: str
    :ivar zones: A list of availability zones denoting the IP allocated for the resource needs to
     come from.
    :vartype zones: list[str]
    :ivar public_ip_allocation_method: The public IP address allocation method. Known values are:
     "Static", "Dynamic".
    :vartype public_ip_allocation_method: str or
     ~azure.mgmt.network.v2022_01_01.models.IPAllocationMethod
    :ivar public_ip_address_version: The public IP address version. Known values are: "IPv4",
     "IPv6".
    :vartype public_ip_address_version: str or ~azure.mgmt.network.v2022_01_01.models.IPVersion
    :ivar ip_configuration: The IP configuration associated with the public IP address.
    :vartype ip_configuration: ~azure.mgmt.network.v2022_01_01.models.IPConfiguration
    :ivar dns_settings: The FQDN of the DNS record associated with the public IP address.
    :vartype dns_settings: ~azure.mgmt.network.v2022_01_01.models.PublicIPAddressDnsSettings
    :ivar ddos_settings: The DDoS protection custom policy associated with the public IP address.
    :vartype ddos_settings: ~azure.mgmt.network.v2022_01_01.models.DdosSettings
    :ivar ip_tags: The list of tags associated with the public IP address.
    :vartype ip_tags: list[~azure.mgmt.network.v2022_01_01.models.IpTag]
    :ivar ip_address: The IP address associated with the public IP address resource.
    :vartype ip_address: str
    :ivar public_ip_prefix: The Public IP Prefix this Public IP Address should be allocated from.
    :vartype public_ip_prefix: ~azure.mgmt.network.v2022_01_01.models.SubResource
    :ivar idle_timeout_in_minutes: The idle timeout of the public IP address.
    :vartype idle_timeout_in_minutes: int
    :ivar resource_guid: The resource GUID property of the public IP address resource.
    :vartype resource_guid: str
    :ivar provisioning_state: The provisioning state of the public IP address resource. Known
     values are: "Succeeded", "Updating", "Deleting", "Failed".
    :vartype provisioning_state: str or ~azure.mgmt.network.v2022_01_01.models.ProvisioningState
    :ivar service_public_ip_address: The service public IP address of the public IP address
     resource.
    :vartype service_public_ip_address: ~azure.mgmt.network.v2022_01_01.models.PublicIPAddress
    :ivar nat_gateway: The NatGateway for the Public IP address.
    :vartype nat_gateway: ~azure.mgmt.network.v2022_01_01.models.NatGateway
    :ivar migration_phase: Migration phase of Public IP Address. Known values are: "None",
     "Prepare", "Commit", "Abort", "Committed".
    :vartype migration_phase: str or
     ~azure.mgmt.network.v2022_01_01.models.PublicIPAddressMigrationPhase
    :ivar linked_public_ip_address: The linked public IP address of the public IP address resource.
    :vartype linked_public_ip_address: ~azure.mgmt.network.v2022_01_01.models.PublicIPAddress
    :ivar delete_option: Specify what happens to the public IP address when the VM using it is
     deleted. Known values are: "Delete", "Detach".
    :vartype delete_option: str or ~azure.mgmt.network.v2022_01_01.models.DeleteOptions
    """

    _validation = {
        'name': {'readonly': True},
        'type': {'readonly': True},
        'etag': {'readonly': True},
        'ip_configuration': {'readonly': True},
        'resource_guid': {'readonly': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'extended_location': {'key': 'extendedLocation', 'type': 'ExtendedLocation'},
        'sku': {'key': 'sku', 'type': 'PublicIPAddressSku'},
        'etag': {'key': 'etag', 'type': 'str'},
        'zones': {'key': 'zones', 'type': '[str]'},
        'public_ip_allocation_method': {'key': 'properties.publicIPAllocationMethod', 'type': 'str'},
        'public_ip_address_version': {'key': 'properties.publicIPAddressVersion', 'type': 'str'},
        'ip_configuration': {'key': 'properties.ipConfiguration', 'type': 'IPConfiguration'},
        'dns_settings': {'key': 'properties.dnsSettings', 'type': 'PublicIPAddressDnsSettings'},
        'ddos_settings': {'key': 'properties.ddosSettings', 'type': 'DdosSettings'},
        'ip_tags': {'key': 'properties.ipTags', 'type': '[IpTag]'},
        'ip_address': {'key': 'properties.ipAddress', 'type': 'str'},
        'public_ip_prefix': {'key': 'properties.publicIPPrefix', 'type': 'SubResource'},
        'idle_timeout_in_minutes': {'key': 'properties.idleTimeoutInMinutes', 'type': 'int'},
        'resource_guid': {'key': 'properties.resourceGuid', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'service_public_ip_address': {'key': 'properties.servicePublicIPAddress', 'type': 'PublicIPAddress'},
        'nat_gateway': {'key': 'properties.natGateway', 'type': 'NatGateway'},
        'migration_phase': {'key': 'properties.migrationPhase', 'type': 'str'},
        'linked_public_ip_address': {'key': 'properties.linkedPublicIPAddress', 'type': 'PublicIPAddress'},
        'delete_option': {'key': 'properties.deleteOption', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        id: Optional[str] = None,
        location: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None,
        extended_location: Optional["_models.ExtendedLocation"] = None,
        sku: Optional["_models.PublicIPAddressSku"] = None,
        zones: Optional[List[str]] = None,
        public_ip_allocation_method: Optional[Union[str, "_models.IPAllocationMethod"]] = None,
        public_ip_address_version: Optional[Union[str, "_models.IPVersion"]] = None,
        dns_settings: Optional["_models.PublicIPAddressDnsSettings"] = None,
        ddos_settings: Optional["_models.DdosSettings"] = None,
        ip_tags: Optional[List["_models.IpTag"]] = None,
        ip_address: Optional[str] = None,
        public_ip_prefix: Optional["_models.SubResource"] = None,
        idle_timeout_in_minutes: Optional[int] = None,
        service_public_ip_address: Optional["_models.PublicIPAddress"] = None,
        nat_gateway: Optional["_models.NatGateway"] = None,
        migration_phase: Optional[Union[str, "_models.PublicIPAddressMigrationPhase"]] = None,
        linked_public_ip_address: Optional["_models.PublicIPAddress"] = None,
        delete_option: Optional[Union[str, "_models.DeleteOptions"]] = None,
        **kwargs
    ):
        """
        :keyword id: Resource ID.
        :paramtype id: str
        :keyword location: Resource location.
        :paramtype location: str
        :keyword tags: A set of tags. Resource tags.
        :paramtype tags: dict[str, str]
        :keyword extended_location: The extended location of the public ip address.
        :paramtype extended_location: ~azure.mgmt.network.v2022_01_01.models.ExtendedLocation
        :keyword sku: The public IP address SKU.
        :paramtype sku: ~azure.mgmt.network.v2022_01_01.models.PublicIPAddressSku
        :keyword zones: A list of availability zones denoting the IP allocated for the resource needs
         to come from.
        :paramtype zones: list[str]
        :keyword public_ip_allocation_method: The public IP address allocation method. Known values
         are: "Static", "Dynamic".
        :paramtype public_ip_allocation_method: str or
         ~azure.mgmt.network.v2022_01_01.models.IPAllocationMethod
        :keyword public_ip_address_version: The public IP address version. Known values are: "IPv4",
         "IPv6".
        :paramtype public_ip_address_version: str or ~azure.mgmt.network.v2022_01_01.models.IPVersion
        :keyword dns_settings: The FQDN of the DNS record associated with the public IP address.
        :paramtype dns_settings: ~azure.mgmt.network.v2022_01_01.models.PublicIPAddressDnsSettings
        :keyword ddos_settings: The DDoS protection custom policy associated with the public IP
         address.
        :paramtype ddos_settings: ~azure.mgmt.network.v2022_01_01.models.DdosSettings
        :keyword ip_tags: The list of tags associated with the public IP address.
        :paramtype ip_tags: list[~azure.mgmt.network.v2022_01_01.models.IpTag]
        :keyword ip_address: The IP address associated with the public IP address resource.
        :paramtype ip_address: str
        :keyword public_ip_prefix: The Public IP Prefix this Public IP Address should be allocated
         from.
        :paramtype public_ip_prefix: ~azure.mgmt.network.v2022_01_01.models.SubResource
        :keyword idle_timeout_in_minutes: The idle timeout of the public IP address.
        :paramtype idle_timeout_in_minutes: int
        :keyword service_public_ip_address: The service public IP address of the public IP address
         resource.
        :paramtype service_public_ip_address: ~azure.mgmt.network.v2022_01_01.models.PublicIPAddress
        :keyword nat_gateway: The NatGateway for the Public IP address.
        :paramtype nat_gateway: ~azure.mgmt.network.v2022_01_01.models.NatGateway
        :keyword migration_phase: Migration phase of Public IP Address. Known values are: "None",
         "Prepare", "Commit", "Abort", "Committed".
        :paramtype migration_phase: str or
         ~azure.mgmt.network.v2022_01_01.models.PublicIPAddressMigrationPhase
        :keyword linked_public_ip_address: The linked public IP address of the public IP address
         resource.
        :paramtype linked_public_ip_address: ~azure.mgmt.network.v2022_01_01.models.PublicIPAddress
        :keyword delete_option: Specify what happens to the public IP address when the VM using it is
         deleted. Known values are: "Delete", "Detach".
        :paramtype delete_option: str or ~azure.mgmt.network.v2022_01_01.models.DeleteOptions
        """
        super(PublicIPAddress, self).__init__(id=id, location=location, tags=tags, **kwargs)
        self.extended_location = extended_location
        self.sku = sku
        self.etag = None
        self.zones = zones
        self.public_ip_allocation_method = public_ip_allocation_method
        self.public_ip_address_version = public_ip_address_version
        self.ip_configuration = None
        self.dns_settings = dns_settings
        self.ddos_settings = ddos_settings
        self.ip_tags = ip_tags
        self.ip_address = ip_address
        self.public_ip_prefix = public_ip_prefix
        self.idle_timeout_in_minutes = idle_timeout_in_minutes
        self.resource_guid = None
        self.provisioning_state = None
        self.service_public_ip_address = service_public_ip_address
        self.nat_gateway = nat_gateway
        self.migration_phase = migration_phase
        self.linked_public_ip_address = linked_public_ip_address
        self.delete_option = delete_option


class PublicIPAddressDnsSettings(msrest.serialization.Model):
    """Contains FQDN of the DNS record associated with the public IP address.

    :ivar domain_name_label: The domain name label. The concatenation of the domain name label and
     the regionalized DNS zone make up the fully qualified domain name associated with the public IP
     address. If a domain name label is specified, an A DNS record is created for the public IP in
     the Microsoft Azure DNS system.
    :vartype domain_name_label: str
    :ivar fqdn: The Fully Qualified Domain Name of the A DNS record associated with the public IP.
     This is the concatenation of the domainNameLabel and the regionalized DNS zone.
    :vartype fqdn: str
    :ivar reverse_fqdn: The reverse FQDN. A user-visible, fully qualified domain name that resolves
     to this public IP address. If the reverseFqdn is specified, then a PTR DNS record is created
     pointing from the IP address in the in-addr.arpa domain to the reverse FQDN.
    :vartype reverse_fqdn: str
    """

    _attribute_map = {
        'domain_name_label': {'key': 'domainNameLabel', 'type': 'str'},
        'fqdn': {'key': 'fqdn', 'type': 'str'},
        'reverse_fqdn': {'key': 'reverseFqdn', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        domain_name_label: Optional[str] = None,
        fqdn: Optional[str] = None,
        reverse_fqdn: Optional[str] = None,
        **kwargs
    ):
        """
        :keyword domain_name_label: The domain name label. The concatenation of the domain name label
         and the regionalized DNS zone make up the fully qualified domain name associated with the
         public IP address. If a domain name label is specified, an A DNS record is created for the
         public IP in the Microsoft Azure DNS system.
        :paramtype domain_name_label: str
        :keyword fqdn: The Fully Qualified Domain Name of the A DNS record associated with the public
         IP. This is the concatenation of the domainNameLabel and the regionalized DNS zone.
        :paramtype fqdn: str
        :keyword reverse_fqdn: The reverse FQDN. A user-visible, fully qualified domain name that
         resolves to this public IP address. If the reverseFqdn is specified, then a PTR DNS record is
         created pointing from the IP address in the in-addr.arpa domain to the reverse FQDN.
        :paramtype reverse_fqdn: str
        """
        super(PublicIPAddressDnsSettings, self).__init__(**kwargs)
        self.domain_name_label = domain_name_label
        self.fqdn = fqdn
        self.reverse_fqdn = reverse_fqdn


class PublicIPAddressListResult(msrest.serialization.Model):
    """Response for ListPublicIpAddresses API service call.

    :ivar value: A list of public IP addresses that exists in a resource group.
    :vartype value: list[~azure.mgmt.network.v2022_01_01.models.PublicIPAddress]
    :ivar next_link: The URL to get the next set of results.
    :vartype next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[PublicIPAddress]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["_models.PublicIPAddress"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        """
        :keyword value: A list of public IP addresses that exists in a resource group.
        :paramtype value: list[~azure.mgmt.network.v2022_01_01.models.PublicIPAddress]
        :keyword next_link: The URL to get the next set of results.
        :paramtype next_link: str
        """
        super(PublicIPAddressListResult, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class PublicIPAddressSku(msrest.serialization.Model):
    """SKU of a public IP address.

    :ivar name: Name of a public IP address SKU. Known values are: "Basic", "Standard".
    :vartype name: str or ~azure.mgmt.network.v2022_01_01.models.PublicIPAddressSkuName
    :ivar tier: Tier of a public IP address SKU. Known values are: "Regional", "Global".
    :vartype tier: str or ~azure.mgmt.network.v2022_01_01.models.PublicIPAddressSkuTier
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'tier': {'key': 'tier', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        name: Optional[Union[str, "_models.PublicIPAddressSkuName"]] = None,
        tier: Optional[Union[str, "_models.PublicIPAddressSkuTier"]] = None,
        **kwargs
    ):
        """
        :keyword name: Name of a public IP address SKU. Known values are: "Basic", "Standard".
        :paramtype name: str or ~azure.mgmt.network.v2022_01_01.models.PublicIPAddressSkuName
        :keyword tier: Tier of a public IP address SKU. Known values are: "Regional", "Global".
        :paramtype tier: str or ~azure.mgmt.network.v2022_01_01.models.PublicIPAddressSkuTier
        """
        super(PublicIPAddressSku, self).__init__(**kwargs)
        self.name = name
        self.tier = tier


class ExtendedLocation(msrest.serialization.Model):
    """ExtendedLocation complex type.

    :ivar name: The name of the extended location.
    :vartype name: str
    :ivar type: The type of the extended location. Known values are: "EdgeZone".
    :vartype type: str or ~azure.mgmt.network.v2022_01_01.models.ExtendedLocationTypes
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        name: Optional[str] = None,
        type: Optional[Union[str, "_models.ExtendedLocationTypes"]] = None,
        **kwargs
    ):
        """
        :keyword name: The name of the extended location.
        :paramtype name: str
        :keyword type: The type of the extended location. Known values are: "EdgeZone".
        :paramtype type: str or ~azure.mgmt.network.v2022_01_01.models.ExtendedLocationTypes
        """
        super(ExtendedLocation, self).__init__(**kwargs)
        self.name = name
        self.type = type


class IPConfiguration(SubResource):
    """IP configuration.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: The name of the resource that is unique within a resource group. This name can be
     used to access the resource.
    :vartype name: str
    :ivar etag: A unique read-only string that changes whenever the resource is updated.
    :vartype etag: str
    :ivar private_ip_address: The private IP address of the IP configuration.
    :vartype private_ip_address: str
    :ivar private_ip_allocation_method: The private IP address allocation method. Known values are:
     "Static", "Dynamic".
    :vartype private_ip_allocation_method: str or
     ~azure.mgmt.network.v2022_01_01.models.IPAllocationMethod
    :ivar subnet: The reference to the subnet resource.
    :vartype subnet: ~azure.mgmt.network.v2022_01_01.models.Subnet
    :ivar public_ip_address: The reference to the public IP resource.
    :vartype public_ip_address: ~azure.mgmt.network.v2022_01_01.models.PublicIPAddress
    :ivar provisioning_state: The provisioning state of the IP configuration resource. Known values
     are: "Succeeded", "Updating", "Deleting", "Failed".
    :vartype provisioning_state: str or ~azure.mgmt.network.v2022_01_01.models.ProvisioningState
    """

    _validation = {
        'etag': {'readonly': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'private_ip_address': {'key': 'properties.privateIPAddress', 'type': 'str'},
        'private_ip_allocation_method': {'key': 'properties.privateIPAllocationMethod', 'type': 'str'},
        'subnet': {'key': 'properties.subnet', 'type': 'Subnet'},
        'public_ip_address': {'key': 'properties.publicIPAddress', 'type': 'PublicIPAddress'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        id: Optional[str] = None,
        name: Optional[str] = None,
        private_ip_address: Optional[str] = None,
        private_ip_allocation_method: Optional[Union[str, "_models.IPAllocationMethod"]] = None,
        subnet: Optional["_models.Subnet"] = None,
        public_ip_address: Optional["_models.PublicIPAddress"] = None,
        **kwargs
    ):
        """
        :keyword id: Resource ID.
        :paramtype id: str
        :keyword name: The name of the resource that is unique within a resource group. This name can
         be used to access the resource.
        :paramtype name: str
        :keyword private_ip_address: The private IP address of the IP configuration.
        :paramtype private_ip_address: str
        :keyword private_ip_allocation_method: The private IP address allocation method. Known values
         are: "Static", "Dynamic".
        :paramtype private_ip_allocation_method: str or
         ~azure.mgmt.network.v2022_01_01.models.IPAllocationMethod
        :keyword subnet: The reference to the subnet resource.
        :paramtype subnet: ~azure.mgmt.network.v2022_01_01.models.Subnet
        :keyword public_ip_address: The reference to the public IP resource.
        :paramtype public_ip_address: ~azure.mgmt.network.v2022_01_01.models.PublicIPAddress
        """
        super(IPConfiguration, self).__init__(id=id, **kwargs)
        self.name = name
        self.etag = None
        self.private_ip_address = private_ip_address
        self.private_ip_allocation_method = private_ip_allocation_method
        self.subnet = subnet
        self.public_ip_address = public_ip_address
        self.provisioning_state = None

class DdosSettings(msrest.serialization.Model):
    """Contains the DDoS protection settings of the public IP.

    :ivar ddos_custom_policy: The DDoS custom policy associated with the public IP.
    :vartype ddos_custom_policy: ~azure.mgmt.network.v2022_01_01.models.SubResource
    :ivar protection_coverage: The DDoS protection policy customizability of the public IP. Only
     standard coverage will have the ability to be customized. Known values are: "Basic",
     "Standard".
    :vartype protection_coverage: str or
     ~azure.mgmt.network.v2022_01_01.models.DdosSettingsProtectionCoverage
    :ivar protected_ip: Enables DDoS protection on the public IP.
    :vartype protected_ip: bool
    """

    _attribute_map = {
        'ddos_custom_policy': {'key': 'ddosCustomPolicy', 'type': 'SubResource'},
        'protection_coverage': {'key': 'protectionCoverage', 'type': 'str'},
        'protected_ip': {'key': 'protectedIP', 'type': 'bool'},
    }

    def __init__(
        self,
        *,
        ddos_custom_policy: Optional["_models.SubResource"] = None,
        protection_coverage: Optional[Union[str, "_models.DdosSettingsProtectionCoverage"]] = None,
        protected_ip: Optional[bool] = None,
        **kwargs
    ):
        """
        :keyword ddos_custom_policy: The DDoS custom policy associated with the public IP.
        :paramtype ddos_custom_policy: ~azure.mgmt.network.v2022_01_01.models.SubResource
        :keyword protection_coverage: The DDoS protection policy customizability of the public IP. Only
         standard coverage will have the ability to be customized. Known values are: "Basic",
         "Standard".
        :paramtype protection_coverage: str or
         ~azure.mgmt.network.v2022_01_01.models.DdosSettingsProtectionCoverage
        :keyword protected_ip: Enables DDoS protection on the public IP.
        :paramtype protected_ip: bool
        """
        super(DdosSettings, self).__init__(**kwargs)
        self.ddos_custom_policy = ddos_custom_policy
        self.protection_coverage = protection_coverage
        self.protected_ip = protected_ip

class IpTag(msrest.serialization.Model):
    """Contains the IpTag associated with the object.

    :ivar ip_tag_type: The IP tag type. Example: FirstPartyUsage.
    :vartype ip_tag_type: str
    :ivar tag: The value of the IP tag associated with the public IP. Example: SQL.
    :vartype tag: str
    """

    _attribute_map = {
        'ip_tag_type': {'key': 'ipTagType', 'type': 'str'},
        'tag': {'key': 'tag', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        ip_tag_type: Optional[str] = None,
        tag: Optional[str] = None,
        **kwargs
    ):
        """
        :keyword ip_tag_type: The IP tag type. Example: FirstPartyUsage.
        :paramtype ip_tag_type: str
        :keyword tag: The value of the IP tag associated with the public IP. Example: SQL.
        :paramtype tag: str
        """
        super(IpTag, self).__init__(**kwargs)
        self.ip_tag_type = ip_tag_type
        self.tag = tag

class NatGateway(Resource):
    """Nat Gateway resource.

    Variables are only populated by the server, and will be ignored when sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :ivar location: Resource location.
    :vartype location: str
    :ivar tags: A set of tags. Resource tags.
    :vartype tags: dict[str, str]
    :ivar sku: The nat gateway SKU.
    :vartype sku: ~azure.mgmt.network.v2022_01_01.models.NatGatewaySku
    :ivar zones: A list of availability zones denoting the zone in which Nat Gateway should be
     deployed.
    :vartype zones: list[str]
    :ivar etag: A unique read-only string that changes whenever the resource is updated.
    :vartype etag: str
    :ivar idle_timeout_in_minutes: The idle timeout of the nat gateway.
    :vartype idle_timeout_in_minutes: int
    :ivar public_ip_addresses: An array of public ip addresses associated with the nat gateway
     resource.
    :vartype public_ip_addresses: list[~azure.mgmt.network.v2022_01_01.models.SubResource]
    :ivar public_ip_prefixes: An array of public ip prefixes associated with the nat gateway
     resource.
    :vartype public_ip_prefixes: list[~azure.mgmt.network.v2022_01_01.models.SubResource]
    :ivar subnets: An array of references to the subnets using this nat gateway resource.
    :vartype subnets: list[~azure.mgmt.network.v2022_01_01.models.SubResource]
    :ivar resource_guid: The resource GUID property of the NAT gateway resource.
    :vartype resource_guid: str
    :ivar provisioning_state: The provisioning state of the NAT gateway resource. Known values are:
     "Succeeded", "Updating", "Deleting", "Failed".
    :vartype provisioning_state: str or ~azure.mgmt.network.v2022_01_01.models.ProvisioningState
    """

    _validation = {
        'name': {'readonly': True},
        'type': {'readonly': True},
        'etag': {'readonly': True},
        'subnets': {'readonly': True},
        'resource_guid': {'readonly': True},
        'provisioning_state': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'sku': {'key': 'sku', 'type': 'NatGatewaySku'},
        'zones': {'key': 'zones', 'type': '[str]'},
        'etag': {'key': 'etag', 'type': 'str'},
        'idle_timeout_in_minutes': {'key': 'properties.idleTimeoutInMinutes', 'type': 'int'},
        'public_ip_addresses': {'key': 'properties.publicIpAddresses', 'type': '[SubResource]'},
        'public_ip_prefixes': {'key': 'properties.publicIpPrefixes', 'type': '[SubResource]'},
        'subnets': {'key': 'properties.subnets', 'type': '[SubResource]'},
        'resource_guid': {'key': 'properties.resourceGuid', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        id: Optional[str] = None,
        location: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None,
        sku: Optional["_models.NatGatewaySku"] = None,
        zones: Optional[List[str]] = None,
        idle_timeout_in_minutes: Optional[int] = None,
        public_ip_addresses: Optional[List["_models.SubResource"]] = None,
        public_ip_prefixes: Optional[List["_models.SubResource"]] = None,
        **kwargs
    ):
        """
        :keyword id: Resource ID.
        :paramtype id: str
        :keyword location: Resource location.
        :paramtype location: str
        :keyword tags: A set of tags. Resource tags.
        :paramtype tags: dict[str, str]
        :keyword sku: The nat gateway SKU.
        :paramtype sku: ~azure.mgmt.network.v2022_01_01.models.NatGatewaySku
        :keyword zones: A list of availability zones denoting the zone in which Nat Gateway should be
         deployed.
        :paramtype zones: list[str]
        :keyword idle_timeout_in_minutes: The idle timeout of the nat gateway.
        :paramtype idle_timeout_in_minutes: int
        :keyword public_ip_addresses: An array of public ip addresses associated with the nat gateway
         resource.
        :paramtype public_ip_addresses: list[~azure.mgmt.network.v2022_01_01.models.SubResource]
        :keyword public_ip_prefixes: An array of public ip prefixes associated with the nat gateway
         resource.
        :paramtype public_ip_prefixes: list[~azure.mgmt.network.v2022_01_01.models.SubResource]
        """
        super(NatGateway, self).__init__(id=id, location=location, tags=tags, **kwargs)
        self.sku = sku
        self.zones = zones
        self.etag = None
        self.idle_timeout_in_minutes = idle_timeout_in_minutes
        self.public_ip_addresses = public_ip_addresses
        self.public_ip_prefixes = public_ip_prefixes
        self.subnets = None
        self.resource_guid = None
        self.provisioning_state = None


class NatGatewayListResult(msrest.serialization.Model):
    """Response for ListNatGateways API service call.

    :ivar value: A list of Nat Gateways that exists in a resource group.
    :vartype value: list[~azure.mgmt.network.v2022_01_01.models.NatGateway]
    :ivar next_link: The URL to get the next set of results.
    :vartype next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[NatGateway]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["_models.NatGateway"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        """
        :keyword value: A list of Nat Gateways that exists in a resource group.
        :paramtype value: list[~azure.mgmt.network.v2022_01_01.models.NatGateway]
        :keyword next_link: The URL to get the next set of results.
        :paramtype next_link: str
        """
        super(NatGatewayListResult, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class NatGatewaySku(msrest.serialization.Model):
    """SKU of nat gateway.

    :ivar name: Name of Nat Gateway SKU. Known values are: "Standard".
    :vartype name: str or ~azure.mgmt.network.v2022_01_01.models.NatGatewaySkuName
    """

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        name: Optional[Union[str, "_models.NatGatewaySkuName"]] = None,
        **kwargs
    ):
        """
        :keyword name: Name of Nat Gateway SKU. Known values are: "Standard".
        :paramtype name: str or ~azure.mgmt.network.v2022_01_01.models.NatGatewaySkuName
        """
        super(NatGatewaySku, self).__init__(**kwargs)
        self.name = name
