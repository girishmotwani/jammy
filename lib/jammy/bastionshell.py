"""
A shell implementation when using a gateway.

"""
import logging
from  jammy.exceptions import *
from jumpssh import SSHSession, TimeoutError, RunCmdError

logger = logging.getLogger(__name__)

class BastionShell():
    """
    Create a shell via a bastion gateway.

    Wrapper class around jumpssh.
    """

    def __init__(self,
                 host,
                 user='ubuntu',
                 password='',
                 private_key_path='',
                 ssh_hop='',
                 port=22):
        """
        Initialize.

        :param host: host/ip to ssh into
        :param user: username to log in with
        :param password: password to log in with
        :param private_key_path: path to the private key
        :param ssh_hop: ssh_hop instance
        :param port: port number to connect to
        """
        # Hostname shell connects to
        self.host = host

        # Port shell connects to
        self.port = port

        # Username shell connects with
        self.user = user

        # Password shell connects with
        self.password = password

        # Private key shell connects with
        self.private_key_path = private_key_path

        # ssh hop
        self.ssh_hop = ssh_hop

        # The underlying Gateway SshSession
        self.gateway_session = None

        # Remote session via Gateway session
        self.remote_session = None

    def connect(self):
        """
        Start up jumpssh and connects to the host.

        :raises SshError: on other error
        """
        logger.info('Connecting to "%s" as "%s"' % (self.host, self.user))

        try:
            self.remote_session = self.get_bastion_ssh_client(
                self.ssh_hop.public_ip,
                self.ssh_hop.username,
                self.host,
                self.user)

        except Exception as e:
            logger.error("Could not connect to %s:%s as user %s: %s",
                         self.host, self.port, self.user, e)
            self.disconnect()
            raise

    def get_bastion_ssh_client(self, b_hostname, b_username, dst_hostname,
                               dst_username):
        """
        Return an instance of jumpssh.SshSession.

        :param b_hostname: Hostname/ip address of the bastion host.
        :param b_username: The username to use when authenticating with the
                           bastion.
        :param dst_hostname: Hostname/ip address of the destination
        :param dst_username: The username to use when auth with the dest host.
        """
        if self.remote_session is None:
            # Connect to bastion on port 22
            self.gateway_session = SSHSession(b_hostname, b_username, private_key_file=self.private_key_path).open()
            logger.info('[IMPORTANT]Connected to bastion at %s:22 as user %s', b_hostname, b_username)
            # Connect to destination on user provided port
            self.remote_session = self.gateway_session.get_remote_session(dst_hostname, username=dst_username, private_key_file=self.private_key_path)
        return self.remote_session

    def upload_file(self, source_file):
        """SCP upload a file from local host to remote machine."""

        ssh_session = self.get_bastion_ssh_client(
            self.ssh_hop.public_ip,
            self.ssh_hop.username,
            self.host,
            self.user)
        
        ssh_session.put(source_file)

    def download_file(self, source_file, dest_file):
        """SCP download a file from remote host to local host."""
        ssh_session = self.get_bastion_ssh_client(
            self.ssh_hop.public_ip,
            self.ssh_hop.username,
            self.host,
            self.user)

        ssh_session.get(remote_path=source_file, local_path=dest_file)

    def exec_command(self, cmd, timeout=360):
        """ Execute command on remote machine."""
        ssh_session = self.get_bastion_ssh_client(
            self.ssh_hop.public_ip,
            self.ssh_hop.username,
            self.host,
            self.user)
        try:
            result = ssh_session.run_cmd(cmd,timeout=timeout)
        except TimeoutError:
            logger.error("Command %s did not complete in the configured timeout", cmd)
            raise CommandTimeout("timeout exceeded")
        except RunCmdError as e:
            logger.error("Command %s execution failed", cmd)
            logger.error("Exception: %s", str(e))
            raise CommandError("command execution failed")
        except Exception as e:
            raise JammyError(str(e))
        return result.output, result.exit_code

    def disconnect(self):
        if self.remote_session and self.remote_session.is_active():
            self.remote_session.close()
        if self.gateway_session and self.gateway_session.is_active():
            self.gateway_session.close()

    def is_connected(self):
        if self.remote_session is None:
            return False
        return self.remote_session.is_active()
