# coding=utf-8
# --------------------------------------------------------------------------
# Code generated by Microsoft (R) AutoRest Code Generator (autorest: 3.0.6349, generator: {generator})
# Changes may cause incorrect behavior and will be lost if the code is regenerated.
# --------------------------------------------------------------------------

try:
    from ._models_py3 import Error
    from ._models_py3 import ErrorDetails
    from ._models_py3 import IpGroup
    from ._models_py3 import IpGroupListResult
    from ._models_py3 import Resource
    from ._models_py3 import SubResource
    from ._models_py3 import TagsObject
    from .version import VERSION
except (SyntaxError, ImportError):
    from ._models import Error  # type: ignore
    from ._models import ErrorDetails  # type: ignore
    from ._models import IpGroup  # type: ignore
    from ._models import IpGroupListResult  # type: ignore
    from ._models import Resource  # type: ignore
    from ._models import SubResource  # type: ignore
    from ._models import TagsObject  # type: ignore
    from .version import VERSION

from ._network_management_client_enums import (
    ProvisioningState,
)

__all__ = [
    'Error',
    'ErrorDetails',
    'IpGroup',
    'IpGroupListResult',
    'Resource',
    'SubResource',
    'TagsObject',
    'ProvisioningState',
]
