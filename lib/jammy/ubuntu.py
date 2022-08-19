
"""
Contains the Ubuntu class representing a ubuntu instance
"""

import logging

from jammy.exceptions import JammyError
from jammy.linux import Linux

logger = logging.getLogger(__name__)


class Ubuntu(Linux):
    """
    The Ubuntu class represents a ubuntu instance
    """
    def __init__(self):
        """
        Build a instance class.
        :param instance_id: instance_id of the instance
        :param role: Role of instance
        """

        super(Ubuntu, self).__init__()
        self.username = 'ubuntu'

    def install(self, app_name=""):
        """
        Installs the requested application via apt-get
        :param: app_name: name of the application to install
        """

        return self.exec_command("DEBIAN_FRONTEND=noninteractive sudo -s "
                                 "apt-get -q -y --force-yes install " +
                                 app_name, timeout=600, raise_on_error=True)

    def is_installed(self, app_name=""):
        """
        Check if requested application is installed
        :param: app_name: name of the application to check

        :return: returns True or False
        """

        (response, exit_status) = self.exec_command("dpkg -s " + app_name)
        if exit_status == 0:
            return True
        else:
            return False

    def update_packages(self):
        """
        Update the apt-get package list
        """

        return self.exec_command(cmd="DEBIAN_FRONTEND=noninteractive "
                                 "sudo apt-get -y update",
                                 timeout=600, raise_on_error=True)

    def create_user(self,
                    username):
        """
        Create a user
        """

        # Create user
        (response, exit_status) = self.exec_command(
            'sudo adduser --disabled-password --gecos "" {0}'.format(
                username))

        if exit_status == 0:
            return True
        else:
            print response
            return False

    def create_group(self,
                     group_name):
        """
        Create a group
        """

        # Create group
        (response, exit_status) = self.exec_command(
            'sudo addgroup {0}'.format(
                group_name))

        if exit_status == 0:
            return True
        else:
            print response
            return False
