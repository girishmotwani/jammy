# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator.
# Changes may cause incorrect behavior and will be lost if the code is
# regenerated.
# --------------------------------------------------------------------------

from .firewall_policy_rule_py3 import FirewallPolicyRule


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

    def __init__(self, *, name: str=None, description: str=None, ip_protocols=None, source_addresses=None, destination_addresses=None, destination_ports=None, translated_address: str=None, translated_port: str=None, source_ip_groups=None, **kwargs) -> None:
        super(NatRule, self).__init__(name=name, description=description, **kwargs)
        self.ip_protocols = ip_protocols
        self.source_addresses = source_addresses
        self.destination_addresses = destination_addresses
        self.destination_ports = destination_ports
        self.translated_address = translated_address
        self.translated_port = translated_port
        self.source_ip_groups = source_ip_groups
        self.rule_type = 'NatRule'
