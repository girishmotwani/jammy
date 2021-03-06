# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class AzureFirewallIpGroups(Model):
    """IpGroups associated with azure firewall.

    Variables are only populated by the server, and will be ignored when
    sending a request.

    :ivar id: Resource ID.
    :vartype id: str
    :ivar change_number: The iteration number.
    :vartype change_number: str
    """

    _validation = {
        'id': {'readonly': True},
        'change_number': {'readonly': True},
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'change_number': {'key': 'changeNumber', 'type': 'str'},
    }

    def __init__(self, **kwargs):
        super(AzureFirewallIpGroups, self).__init__(**kwargs)
        self.id = None
        self.change_number = None
