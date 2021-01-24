# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator (autorest: 3.0.6349, generator: {generator})
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

from typing import Dict, List, Optional

from azure.core.exceptions import HttpResponseError
import msrest.serialization


class Error(msrest.serialization.Model):
    """Common error representation.

    :param code: Error code.
    :type code: str
    :param message: Error message.
    :type message: str
    :param target: Error target.
    :type target: str
    :param details: Error details.
    :type details: list[~network_management_client.models.ErrorDetails]
    :param inner_error: Inner error message.
    :type inner_error: str
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
        'target': {'key': 'target', 'type': 'str'},
        'details': {'key': 'details', 'type': '[ErrorDetails]'},
        'inner_error': {'key': 'innerError', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        code: Optional[str] = None,
        message: Optional[str] = None,
        target: Optional[str] = None,
        details: Optional[List["ErrorDetails"]] = None,
        inner_error: Optional[str] = None,
        **kwargs
    ):
        super(Error, self).__init__(**kwargs)
        self.code = code
        self.message = message
        self.target = target
        self.details = details
        self.inner_error = inner_error


class ErrorDetails(msrest.serialization.Model):
    """Common error details representation.

    :param code: Error code.
    :type code: str
    :param target: Error target.
    :type target: str
    :param message: Error message.
    :type message: str
    """

    _attribute_map = {
        'code': {'key': 'code', 'type': 'str'},
        'target': {'key': 'target', 'type': 'str'},
        'message': {'key': 'message', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        code: Optional[str] = None,
        target: Optional[str] = None,
        message: Optional[str] = None,
        **kwargs
    ):
        super(ErrorDetails, self).__init__(**kwargs)
        self.code = code
        self.target = target
        self.message = message


class Resource(msrest.serialization.Model):
    """Common resource representation.

    Variables are only populated by the server, and will be ignored when sending a request.

    :param id: Resource ID.
    :type id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param location: Resource location.
    :type location: str
    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
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
        super(Resource, self).__init__(**kwargs)
        self.id = id
        self.name = None
        self.type = None
        self.location = location
        self.tags = tags


class IpGroup(Resource):
    """The IpGroups resource information.

    Variables are only populated by the server, and will be ignored when sending a request.

    :param id: Resource ID.
    :type id: str
    :ivar name: Resource name.
    :vartype name: str
    :ivar type: Resource type.
    :vartype type: str
    :param location: Resource location.
    :type location: str
    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    :ivar etag: A unique read-only string that changes whenever the resource is updated.
    :vartype etag: str
    :ivar provisioning_state: The provisioning state of the IpGroups resource. Possible values
     include: "Succeeded", "Updating", "Deleting", "Failed".
    :vartype provisioning_state: str or ~network_management_client.models.ProvisioningState
    :param ip_addresses: IpAddresses/IpAddressPrefixes in the IpGroups resource.
    :type ip_addresses: list[str]
    :ivar firewalls: List of references to Firewall resources that this IpGroups is associated
     with.
    :vartype firewalls: list[~network_management_client.models.SubResource]
    :ivar firewall_policies: List of references to Firewall Policies resources that this IpGroups
     is associated with.
    :vartype firewall_policies: list[~network_management_client.models.SubResource]
    """

    _validation = {
        'name': {'readonly': True},
        'type': {'readonly': True},
        'etag': {'readonly': True},
        'provisioning_state': {'readonly': True},
        'firewalls': {'readonly': True},
        'firewall_policies': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'location': {'key': 'location', 'type': 'str'},
        'tags': {'key': 'tags', 'type': '{str}'},
        'etag': {'key': 'etag', 'type': 'str'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'ip_addresses': {'key': 'properties.ipAddresses', 'type': '[str]'},
        'firewalls': {'key': 'properties.firewalls', 'type': '[SubResource]'},
        'firewall_policies': {'key': 'properties.firewallPolicies', 'type': '[SubResource]'},
    }

    def __init__(
        self,
        *,
        id: Optional[str] = None,
        location: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None,
        ip_addresses: Optional[List[str]] = None,
        **kwargs
    ):
        super(IpGroup, self).__init__(id=id, location=location, tags=tags, **kwargs)
        self.etag = None
        self.provisioning_state = None
        self.ip_addresses = ip_addresses
        self.firewalls = None
        self.firewall_policies = None


class IpGroupListResult(msrest.serialization.Model):
    """Response for the ListIpGroups API service call.

    :param value: The list of IpGroups information resources.
    :type value: list[~network_management_client.models.IpGroup]
    :param next_link: URL to get the next set of results.
    :type next_link: str
    """

    _attribute_map = {
        'value': {'key': 'value', 'type': '[IpGroup]'},
        'next_link': {'key': 'nextLink', 'type': 'str'},
    }

    def __init__(
        self,
        *,
        value: Optional[List["IpGroup"]] = None,
        next_link: Optional[str] = None,
        **kwargs
    ):
        super(IpGroupListResult, self).__init__(**kwargs)
        self.value = value
        self.next_link = next_link


class SubResource(msrest.serialization.Model):
    """Reference to another subresource.

    :param id: Resource ID.
    :type id: str
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
        super(SubResource, self).__init__(**kwargs)
        self.id = id


class TagsObject(msrest.serialization.Model):
    """Tags object for patch operations.

    :param tags: A set of tags. Resource tags.
    :type tags: dict[str, str]
    """

    _attribute_map = {
        'tags': {'key': 'tags', 'type': '{str}'},
    }

    def __init__(
        self,
        *,
        tags: Optional[Dict[str, str]] = None,
        **kwargs
    ):
        super(TagsObject, self).__init__(**kwargs)
        self.tags = tags