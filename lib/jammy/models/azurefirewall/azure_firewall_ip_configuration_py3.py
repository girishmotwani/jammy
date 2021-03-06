# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .sub_resource_py3 import SubResource


class AzureFirewallIPConfiguration(SubResource):
    """IP configuration of an Azure Firewall.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param id: Resource ID.
    :type id: str
    :ivar private_ip_address: The Firewall Internal Load Balancer IP to be
     used as the next hop in User Defined Routes.
    :vartype private_ip_address: str
    :param subnet: Reference to the subnet resource. This resource must be
     named 'AzureFirewallSubnet' or 'AzureFirewallManagementSubnet'.
    :type subnet: ~azurefirewall.models.SubResource
    :param public_ip_address: Reference to the PublicIP resource. This field
     is a mandatory input if subnet is not null.
    :type public_ip_address: ~azurefirewall.models.SubResource
    :ivar provisioning_state: The provisioning state of the Azure firewall IP
     configuration resource. Possible values include: 'Succeeded', 'Updating',
     'Deleting', 'Failed'
    :vartype provisioning_state: str or
     ~azurefirewall.models.ProvisioningState
    :param name: Name of the resource that is unique within a resource group.
     This name can be used to access the resource.
    :type name: str
    :ivar etag: A unique read-only string that changes whenever the resource
     is updated.
    :vartype etag: str
    :ivar type: Type of the resource.
    :vartype type: str
    """

    _validation = {
        'private_ip_address': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'etag': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'private_ip_address': {'key': 'properties.privateIPAddress', 'type': 'str'},
        'subnet': {'key': 'properties.subnet', 'type': 'SubResource'},
        'public_ip_address': {'key': 'properties.publicIPAddress', 'type': 'SubResource'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, *, id: str=None, subnet=None, public_ip_address=None, name: str=None, **kwargs) -> None:
        super(AzureFirewallIPConfiguration, self).__init__(id=id, **kwargs)
        self.private_ip_address = None
        self.subnet = subnet
        self.public_ip_address = public_ip_address
        self.provisioning_state = None
        self.name = name
        self.etag = None
        self.type = None
