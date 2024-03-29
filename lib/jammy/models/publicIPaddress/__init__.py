# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator (autorest: 3.0.6349, generator: {generator})
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import PublicIPAddressSku
    from ._models_py3 import PublicIPAddressDnsSettings
    from ._models_py3 import Resource
    from ._models_py3 import SubResource
    from ._models_py3 import PublicIPAddress
    from ._models_py3 import ExtendedLocation
    from ._models_py3 import IPConfiguration
    from ._models_py3 import DdosSettings
    from ._models_py3 import NatGateway
    from ._models_py3 import IpTag
    from .version import VERSION
except (SyntaxError, ImportError):
    from .version import VERSION

from ._network_management_client_enums import (
    ProvisioningState,
)

__all__ = [
    'Resource',
    'ExtendedLocation',
    'SubResource',
    'PublicIPAddress',
    'PublicIPAddressSku',
    'PublicIPAddressDnsSettings',
    'ProvisioningState',
    'IPConfiguration',
    'IpTag',
    'DdosSettings',
    'NatGateway',
]
