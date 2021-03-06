# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .firewall_policy_rule import FirewallPolicyRule


class NatRule(FirewallPolicyRule):
    """Rule of type nat.

    All required parameters must be populated in order to send to Azure.

    :param name: Name of the rule.
    :type name: str
    :param description: Description of the rule.
    :type description: str
    :param rule_type: Required. Constant filled by server.
    :type rule_type: str
    :param ip_protocols: Array of FirewallPolicyRuleNetworkProtocols.
    :type ip_protocols: list[str or
     ~firewallpolicy.models.FirewallPolicyRuleNetworkProtocol]
    :param source_addresses: List of source IP addresses for this rule.
    :type source_addresses: list[str]
    :param destination_addresses: List of destination IP addresses or Service
     Tags.
    :type destination_addresses: list[str]
    :param destination_ports: List of destination ports.
    :type destination_ports: list[str]
    :param translated_address: The translated address for this NAT rule.
    :type translated_address: str
    :param translated_port: The translated port for this NAT rule.
    :type translated_port: str
    :param source_ip_groups: List of source IpGroups for this rule.
    :type source_ip_groups: list[str]
    """

    _validation = {
        'rule_type': {'required': True},
    }

    _attribute_map = {
        'name': {'key': 'name', 'type': 'str'},
        'description': {'key': 'description', 'type': 'str'},
        'rule_type': {'key': 'ruleType', 'type': 'str'},
        'ip_protocols': {'key': 'ipProtocols', 'type': '[str]'},
        'source_addresses': {'key': 'sourceAddresses', 'type': '[str]'},
        'destination_addresses': {'key': 'destinationAddresses', 'type': '[str]'},
        'destination_ports': {'key': 'destinationPorts', 'type': '[str]'},
        'translated_address': {'key': 'translatedAddress', 'type': 'str'},
        'translated_port': {'key': 'translatedPort', 'type': 'str'},
        'source_ip_groups': {'key': 'sourceIpGroups', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(NatRule, self).__init__(**kwargs)
        self.ip_protocols = kwargs.get('ip_protocols', None)
        self.source_addresses = kwargs.get('source_addresses', None)
        self.destination_addresses = kwargs.get('destination_addresses', None)
        self.destination_ports = kwargs.get('destination_ports', None)
        self.translated_address = kwargs.get('translated_address', None)
        self.translated_port = kwargs.get('translated_port', None)
        self.source_ip_groups = kwargs.get('source_ip_groups', None)
        self.rule_type = 'NatRule'
