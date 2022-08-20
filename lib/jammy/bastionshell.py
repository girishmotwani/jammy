"""
A shell implementation when using a gateway.

Copyright 2016 Bracket Computing, Inc.
"""
import logging

from scp import SCPClient

from jammy.sshshell import SshShell

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logging.getLogger("paramiko").setLevel(logging.WARNING)


class BastionShell(SshShell):
    """
    Create a shell via a bastion.

    Wrapper class around paramiko and sshshell.
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

        # The underlying paramiko ssh client
        self.ssh_client = None

        # paramiko.Transport object
        self.transport = None

        # sftp object to upload/download files
        # from the instance
        self._sftp_client = None

    def connect(self):
        """
        Start up paramiko and connects to the host.

        :raises SshError: on other error
        """
        logger.info('Connecting to "%s" as "%s"' % (self.host, self.user))

        try:
            self.ssh_client = self.get_bastion_ssh_client(
                self.ssh_hop.public_ip,
                self.ssh_hop.username,
                self.host,
                self.user)

            self.transport = self.ssh_client.get_transport()
            self.transport.set_keepalive(30)

        except Exception as e:
            logger.error("Could not connect to %s:%s as user %s: %s",
                         self.host, self.port, self.user, e)
            self.disconnect()
            raise

    def get_bastion_ssh_client(self, b_hostname, b_username, dst_hostname,
                               dst_username):
        """
        Return an instance of paramiko.

        SSHClient that is connected to the supplied instance through the
        given bastion.

        :param b_hostname: Hostname/ip address of the bastion host.
        :param b_username: The username to use when authenticating with the
                           bastion.
        :param dst_hostname: Hostname/ip address of the destination
        :param dst_username: The username to use when auth with the dest host.
        """
        # Connect to bastion on port 22
        b_ssh = self.get_ssh_client(b_hostname, b_username, port=22)
        # Connect to destination on user provided port
        dst_chan = b_ssh.get_transport().open_channel(
            'direct-tcpip',
            dest_addr=(dst_hostname, self.port),
            src_addr=('localhost', 10000))
        dst_ssh = self.get_ssh_client(dst_hostname, dst_username,
                                      sock=dst_chan)
        return BastionSSHClient(b_ssh, dst_ssh)

    def upload_file(self, source_file, dest_file):
        """SCP upload a file from local host to remote machine."""
        ssh_client = self.get_bastion_ssh_client(
            self.ssh_hop.public_ip,
            self.ssh_hop.username,
            self.host,
            self.user)

        with SCPClient(ssh_client.get_transport()) as scp_client:
            scp_client.put(source_file, dest_file)

    def download_file(self, source_file, dest_file):
        """SCP download a file from remote host to local host."""
        ssh_client = self.get_bastion_ssh_client(
            self.ssh_hop.public_ip,
            self.ssh_hop.username,
            self.host,
            self.user)

        with SCPClient(ssh_client.get_transport()) as scp_client:
            scp_client.get(source_file, dest_file)


class BastionSSHClient(object):
    """Bind the lifetime of the bastion client to the tunneled ssh client."""

    def __init__(self, b_ssh, ssh):
        """Create a bastion SSH client."""
        self.b_ssh = b_ssh
        self.ssh = ssh

    def __getattr__(self, name):
        """Return a attribute."""
        return getattr(self.ssh, name)
