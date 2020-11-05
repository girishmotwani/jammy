# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from msrest.serialization import Model


class FirewallPolicyFilterRuleCollectionAction(Model):
    """Properties of the FirewallPolicyFilterRuleCollectionAction.

    :param type: The type of action. Possible values include: 'Allow', 'Deny'
    :type type: str or
     ~firewallpolicy.models.FirewallPolicyFilterRuleCollectionActionType
    """

    _attribute_map = {
        'type': {'key': 'type', 'type': 'str'},
    }

    def __init__(self, *, type=None, **kwargs) -> None:
        super(FirewallPolicyFilterRuleCollectionAction, self).__init__(**kwargs)
        self.type = type
