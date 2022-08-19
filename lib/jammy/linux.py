
"""
Contains the Linux class representing a linux instance
This class is meant to be subclassed by Ubuntu/Centos classes etc.
"""

import logging
import threading
import time
import subprocess

from jammy.waituntil import retry_on_exception
from jammy.waituntil import is_sshable
from jammy.exceptions import CommandError
from jammy.instance import Instance
from jammy.waituntil import is_in_response
from jammy.waituntil import waituntil


logger = logging.getLogger(__name__)

RETRY_TIMEOUT_S = 15


class Linux(Instance):
    """
    The Linux class represents a Linux instance
    """
    def __init__(self):
        super(Linux, self).__init__()

    def wait_for_reboot(self):
        """
        Calls a long command and waits for it to be interrupted by a reboot
        """
        try:
            self.exec_command("sleep 10000000")
        except:
            logging.debug("Command was interrupted so we assume that we have "
                          "started rebooting")

    def reboot(self):
        """
        Function To reboot the instance

        Since it takes a while for the reboot to start we execute a long
        sleep that will get interrupted when the instance actually restarts
        """

        logger.info("Rebooting instance %s", self)
        self.exec_command("sudo -s reboot")
        self.wait_for_reboot()

    def ping(self, destination_ip, seconds_to_wait=5):
        """
        Ping desination ip and wait until response
        """

        # Ping destination ip and wait for response
        (response, exit_status) = self.exec_command(
            "ping {0} -c 1 -w {1}".format(destination_ip,
                                          seconds_to_wait))

        if exit_status == 0:
            return True
        else:
            return False

    def ping_a_port(self,
                    destination_ip,
                    destination_port):
        """
        Ping a destination ip:port to see if its listening
        """

        # Use netcat to check if remote ip:port is listening
        (response, exit_status) = self.exec_command(
            "nc -zvv {0} {1}".format(destination_ip,
                                     destination_port))

        if exit_status == 0:
            return True
        else:
            return False

    def set_user_password(self,
                          username,
                          password):
        """
        Set user password
        """

        # Set user password
        (response, exit_status) = self.exec_command(
            'echo "{0}:{1}"| sudo chpasswd'.format(
                username, password))

        if exit_status == 0:
            return True
        else:
            return False

    def is_process_running(self, pid):
        """
        Check if the process is running
        :param pid: pid of the process to check

        :return: return True or False
        """

        response, exit_status = self.exec_command('kill -0 {0}'.format(pid))
        return exit_status == 0

    def start_service(self, service_name):
        """
        Start a service
        :param service_name: name of service to start
        """

        (response, exit_status) = self.exec_command(
            'sudo service {0} start'.format(service_name))

        if exit_status != 0:
            raise CommandError(response)

    def stop_service(self, service_name):
        """
        Stop a service
        :param service_name: name of service to stop
        """

        (response, exit_status) = self.exec_command(
            'sudo service {0} stop'.format(service_name))

        if exit_status != 0:
            raise CommandError(response)

    def restart_service(self, service_name):
        """
        Restart a service
        :param service_name: name of service to restart
        """

        (response, exit_status) = self.exec_command(
            'sudo service {0} restart'.format(service_name))

        if exit_status != 0:
            raise CommandError(response)
