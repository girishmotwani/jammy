
"""
Contains the Instance class representing a single instance
"""

import logging
import time

from jammy.bastionshell import BastionShell

RETRY_TIMEOUT_S = 15
logger = logging.getLogger(__name__)


class Instance(object):
    """
    The Instance class represents an instance in Azure 
    """

    def __init__(self):
        """
        Build an instance class.
        """
        self.dst_port = 22

        self._name = None
        self._hostname = None
        self._private_key_path = None
        self._private_ip = None
        self._public_ip = None
        self._ssh_hop = None
        self._username = None
        self._password = None
        self._shell = None
        self._sftp_client = None

    def __repr__(self):
        return "%s name: %s" % (self.__class__.__name__,
                                self.name)

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def hostname(self):
        if not self._hostname:
            self._hostname = self.exec_command("hostname",
                                               raise_on_error=True)[0].strip()
        return self._hostname

    @property
    def private_key_path(self):
        return self._private_key_path

    @private_key_path.setter
    def private_key_path(self, value):
        self._private_key_path = value

    @property
    def private_ip(self):
        return self._private_ip

    @private_ip.setter
    def private_ip(self, value):
        self._private_ip = value

    @property
    def public_ip(self):
        return self._public_ip

    @public_ip.setter
    def public_ip(self, value):
        self._public_ip = value

    @property
    def ssh_hop(self):
        return self._ssh_hop

    @ssh_hop.setter
    def ssh_hop(self, value):
        self._ssh_hop = value

    @property
    def username(self):
        return self._username

    @username.setter
    def username(self, value):
        self._username = value

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, value):
        self._password = value

    @property
    def shell(self):
        """ A shell for executing commands
        """
        if not self._shell or not self._shell.is_connected:
            self._shell = self.get_shell()
        return self._shell

    def get_shell(self):
        """ Shell for executing commands, use if you need more than one
            connection running at the same time...

            Use self.shell in normal cases.
        """
        shell = None
        if self.username is None:
            logger.error('Instance must have a username')
            return None

        if self.ssh_hop is None:
            logger.error('Instance should have a ssh hop')
            return None
        else:
            shell = BastionShell(self.private_ip,
                                 self.username,
                                 self.password,
                                 self.private_key_path,
                                 self.ssh_hop,
                                 self.dst_port)
        shell.connect()
        return shell

    def disconnect(self):
        if self._shell:
            self._shell.disconnect()
            del self._shell
            self._shell = None

    def exec_command(self, cmd, type='ssh', timeout=360, retries=1,
                     raise_on_error=False):
        """
        Execute the given command
        :param cmd: the command to be executed
        :param type: The type of underlying mechanism. Default to ssh
        :param raise_on_error: Raise Exception if exit status is not 0

        :return: output for the command.

        :raises JammyError: unknown shell
        """
        if type != 'ssh':
            raise JammyError("unknown shell")

        for i in range(retries):
            output, exit_status = self.shell.exec_command(cmd, timeout=timeout)

            if exit_status == 0:
                break

            logger.info("error executing `%s`, exit_status %d, command: %s",
                        cmd, exit_status, output)

            if i < retries - 1:
                logger.info("Sleeping for %d seconds before retrying",
                            RETRY_TIMEOUT_S)
                time.sleep(RETRY_TIMEOUT_S)

        if raise_on_error:
            assert exit_status == 0, output

        return output, exit_status
