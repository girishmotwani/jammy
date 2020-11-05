# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .sub_resource_py3 import SubResource


class FirewallPolicyRuleCollectionGroup(SubResource):
    """Rule Collection Group resource.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :param id: Resource ID.
    :type id: str
    :param priority: Priority of the Firewall Policy Rule Collection Group
     resource.
    :type priority: int
    :param rule_collections: Group of Firewall Policy rule collections.
    :type rule_collections:
     list[~firewallpolicy.models.FirewallPolicyRuleCollection]
    :ivar provisioning_state: The provisioning state of the firewall policy
     rule collection group resource. Possible values include: 'Succeeded',
     'Updating', 'Deleting', 'Failed'
    :vartype provisioning_state: str or
     ~firewallpolicy.models.ProvisioningState
    :param name: The name of the resource that is unique within a resource
     group. This name can be used to access the resource.
    :type name: str
    :ivar etag: A unique read-only string that changes whenever the resource
     is updated.
    :vartype etag: str
    :ivar type: Rule Group type.
    :vartype type: str
    """

    _validation = {
        'priority': {'maximum': 65000, 'minimum': 100},
        'provisioning_state': {'readonly': True},
        'etag': {'readonly': True},
        'type': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'priority': {'key': 'properties.priority', 'type': 'int'},
        'rule_collections': {'key': 'properties.ruleCollections', 'type': '[FirewallPolicyRuleCollection]'},
        'provisioning_state': {'key': 'properties.provisioningState', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'etag': {'key': 'etag', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, *, id: str=None, priority: int=None, rule_collections=None, name: str=None, **kwargs) -> None:
        super(FirewallPolicyRuleCollectionGroup, self).__init__(id=id, **kwargs)
        self.priority = priority
        self.rule_collections = rule_collections
        self.provisioning_state = None
        self.name = name
        self.etag = None
        self.type = None