
"""
Contains the Jumpbox class representing a jumpbox instance
"""

import logging

from jammy.ubuntu import Ubuntu

logger = logging.getLogger(__name__)


class JumpBox(Ubuntu):
    """
    The Jumpbox class represents a jumpbox instance
    """

    def __init__(self):
        """
        Build a instance class.
        :param instance_id: instance_id of the instance
        :param role: Role of instance
        """

        super(JumpBox, self).__init__()
        self.username = 'gsauser'
