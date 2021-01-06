"""
SSH shell implementation.

"""
import logging
import select
import socket
import StringIO
import subprocess
import threading
import time
import uuid

import paramiko

from scp import SCPClient

from jammy.exceptions import JammyError, CommandError, CommandTimeout, SshError
from jammy.waituntil import retry_on_exception

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logging.getLogger("paramiko").setLevel(logging.WARNING)

CHUNK_SIZE = 4096
RETRY_TIMEOUT_S = 15


def _maybe_add_password(command, password):
    """
    Add sudo password to command if required. Else NOOP.
    in: sudo apt-get install
    out: echo 'password' | sudo -S apt-get install
    """
    if not password or 'sudo' not in command:  # or 'sudo -S' in command:
        return command

    # Handle commands that are chained with &&
    blocks = command.split('&&')

    def fix_block(block):
        """Adds sudo and password where needed"""
        if 'sudo' in block and 'sudo -S' not in block:
            # Split the command string into a list of words
            words = block.split()

            for i, word in enumerate(words):
                if word == 'sudo':
                    words.insert(i + 1, '-S')
                    break

            words.insert(0, "echo '%s' |" % password)

            return ' '.join(words)

        return block

    fixed_blocks = [fix_block(block) for block in blocks]

    return '&&'.join(fixed_blocks)


class SshShell(object):
    """Wrapper class around paramiko."""

    def __init__(self,
                 host,
                 user='ubuntu',
                 password='',
                 private_key_path=None,
                 port=22):
        """
        Initializer.

        :param host: host/ip to ssh into
        :param user: username to log in with
        :param password: password to log in with
        :param private_key_path: path to the private key
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

        # The underlying paramiko ssh client
        self.ssh_client = None

        # paramiko.Transport object
        self.transport = None

        # sftp object to upload/download files
        # from the instance
        self.sftp_client = None

    def connect(self, timeout=60):
        """
        Start up paramiko and connects to the host.

        :param timeout: an optional timeout (in seconds) for waiting for
                        ssh banner coming out. Defaults to 60 seconds.

        :raises SshError: on other error
        """
        try:
            self.ssh_client = self.get_ssh_client(self.host, self.user,
                                                  sock=None, timeout=timeout,
                                                  port=self.port)
            self.transport = self.ssh_client.get_transport()
            self.transport.set_keepalive(30)

        except Exception as e:
            logger.error('Could not connect to %s:%s as user "%s". Error: %s',
                         self.host, self.port, self.user, e)
            self.disconnect()
            raise

    def disconnect(self):
        """Disconnect from the host."""
        if self.transport:
            self.transport.close()

        if self.ssh_client:
            self.ssh_client.close()

        # Clear these to make sure we get a clean reconnect
        self.ssh_client = None
        self.transport = None

    def get_end_time(self, timeout):
        # no timeout means timeout in 1 hour
        if not timeout:
            return time.time() + float("inf")

        return time.time() + timeout

    def _forwarder(self, host, port):
        """ Trivial forwarder. We only support 1 session at a time.
        """
        while True:
            chan = None
            while chan is None:
                chan = self.transport.accept(5)

            sock = socket.socket()
            try:
                sock.connect((host, port))
            except Exception as e:
                logger.error('forwarding request to %s:%d failed: %r' %
                             (host, port, e))
                chan.close()
                continue

            logger.debug('Tunnel open %r -> %r -> %r' % (chan.origin_addr,
                         chan.getpeername(), (host, port)))

            while True:
                r, w, x = select.select([sock, chan], [], [])
                if sock in r:
                    data = sock.recv(16384)
                    if len(data) == 0:
                        break
                    chan.sendall(data)
                if chan in r:
                    data = chan.recv(16384)
                    if len(data) == 0:
                        break
                    sock.sendall(data)

            chan.close()
            sock.close()
            logger.debug('Tunnel closed from %r', chan.origin_addr)

    def forward_remote(self, lport, address):
        """ Forward port 'lport' on the host we're connected to with
            SSH to a remote server at 'address', where 'address' is a
            standard '(host, port)' tuple.
            If 'address' is None, return the transport to accept on.
            Otherwise, start a thread that connects the transport to
            the remote server.
        """
        if (not self.transport) or (not self.transport.is_active()):
            self.connect()
        self.transport.request_port_forward('', lport)
        if address is None:
            return self.transport
        thr = threading.Thread(target=self._forwarder, args=address)
        thr.setDaemon(True)
        thr.start()
        return None

    def _read_channel(self, channel, stdout, stderr):
        """Read the channels stdout and stderr until there is no more data"""
        while True:
            stdout_data = None
            stderr_data = None
            if channel.recv_ready():
                stdout_data = channel.recv(CHUNK_SIZE)
                stdout.write(stdout_data)
            if channel.recv_stderr_ready():
                stderr_data = channel.recv_stderr(CHUNK_SIZE)
                stderr.write(stderr_data)
            if not stdout_data and not stderr_data:
                break

    def _exec_command(self, channel, command, timeout):
        """Executes the command on the given channel

        :raises CommandTimeout: on command timeout
        :raises socket.timeout: on channel timeout

        :return: output, exit_code
        """
        end_time = self.get_end_time(timeout)

        channel.exec_command(command)
        stdout = StringIO.StringIO()
        stderr = StringIO.StringIO()

        # Read until we time out or the channel closes
        while time.time() < end_time:
            self._read_channel(channel, stdout, stderr)

            if channel.exit_status_ready():
                break

            if int(time.time()) % 60 == 0:
                logging.info('Still waiting for command "%s"', command)

            time.sleep(1)

        self._read_channel(channel, stdout, stderr)

        if not channel.exit_status_ready():
            raise CommandTimeout(
                'Command "%s" timed out after %d seconds. Output so far: '
                '(%s,%s)' % (command, timeout, stdout.getvalue(),
                             stderr.getvalue()))
        exit_status = channel.recv_exit_status()

        # recv_exit_status might flush out some more data to the output
        # according to the paramiko documentation
        self._read_channel(channel, stdout, stderr)

        return stdout.getvalue(), stderr.getvalue(), exit_status

    def exec_command(self, command, timeout=120, except_on_error=False):
        """
        Execute the given command.

        This is for a single command only, no
        shell is running, so an exec_command cannot use environment variables
        or directory changes etc. from a previous exec_command.

        :param command: command to send
        :param timeout: seconds to wait for command to finish. None to disable
        :param except_on_error: If True, throw a CommandError exception if
                                the command returns a non-zero return code

        :raises SshError: if not connected
        :raises CommandError: on non-zero return code from the command and
                              except_on_error is True
        :raises CommandTimeout: on timeout

        :return: (output, exit_code) for the command.
        """
        command_with_password = _maybe_add_password(command, self.password)
        if command_with_password != command:
            logger.info('%s:%s Executing command "%s" with password',
                        self.host, self.port, command)
            command = command_with_password
        else:
            logger.info('%s:%s Executing command "%s"', self.host, self.port,
                        command)

        # connect if ssh is not connected
        if not self.transport or not self.transport.is_active():
            self.connect()

        channel = self._open_ssh_session(timeout)
        agent = paramiko.agent.AgentRequestHandler(channel)
        channel.get_pty()

        # Put stderr into the same output as stdout.
        channel.set_combine_stderr(True)

        try:
            output, _, exit_status = self._exec_command(channel, command,
                                                        timeout)
        except socket.timeout:
            logger.exception('Channel timed out')
            raise CommandTimeout(
                'Command "%s" failed due to socket timeout. Output so far: '
                '%s' % (command, output))
        finally:
            agent.close()
            channel.close()

        # If the command failed and the user wants an exception, throw it!
        if exit_status != 0 and except_on_error:
            raise CommandError('Command "%s" returned %d with the output:\n%s'
                               % (command, exit_status, output))

        if output:
            logger.info("Command output: %s", output)
        else:
            logger.info('Command finished without output')

        return (output, exit_status)

    def _open_ssh_session(self, timeout):
        try:
            channel = retry_on_exception(self.transport.open_session)
        except:
            self.disconnect()
            self.connect()

            channel = retry_on_exception(self.transport.open_session)

        channel.settimeout(timeout)
        return channel

    def exec_command_separate_stdout_stderr(self, command, timeout=120,
                                            except_on_error=False):
        """
        Execute the given command, returns stdout and stderr seperately.

        The reason for more or less copy pasting exec_command is that the
        return type of this function is different, and it also does not
        get_pty. Because of these small differences and the fact that
        exec_command is used everywhere in Yolo, we want this in its own
        function.

        This is for a single command only, no
        shell is running, so an exec_command cannot use environment variables
        or directory changes etc. from a previous exec_command.

        NOTE: Running with the combine_stderr flag set to False will disallow
              running sudo commands in some cases, so only do this if you
              really need to separate the output

        :param command: command to send
        :param timeout: seconds to wait for command to finish. None to disable
        :param except_on_error: If True, throw a CommandError exception if
                                the command returns a non-zero return code

        :raises SshError: if not connected
        :raises CommandError: on non-zero return code from the command and
                              except_on_error is True
        :raises CommandTimeout: on timeout

        :return: (stdout, stderr, exit_code) for the command
        """
        command_with_password = _maybe_add_password(command, self.password)
        if command_with_password != command:
            logger.info('Executing command "%s" with password', command)
            command = command_with_password
        else:
            logger.info('Executing command "%s"', command)

        # connect if ssh is not connected
        if not self.transport or not self.transport.is_active():
            self.connect()

        channel = self._open_ssh_session(timeout)
        agent = paramiko.agent.AgentRequestHandler(channel)

        # Whether or not to put stdout and stdin in the same output
        channel.set_combine_stderr(False)

        try:
            stdout, stderr, exit_status = self._exec_command(channel, command,
                                                             timeout)
        except socket.timeout:
            logger.exception('Channel timed out')
            raise CommandTimeout(
                'Command "%s" failed due to socket timeout. Output so far: '
                '(%s, %s)' % (command, stdout, stderr))
        finally:
            agent.close()
            channel.close()

        # If the command failed and the user wants an exception, throw it!
        if exit_status != 0 and except_on_error:
            raise CommandError(
                'Command "%s" returned %d with the output:\n(%s,%s)'
                % (command, exit_status, stdout, stderr))

        if stdout or stderr:
            logger.info("Command output: (%s,%s)", stdout, stderr)

        return (stdout, stderr, exit_status)

    def exec_background(self, command, except_on_error=False):
        """
        Execute a command that starts a background process.
        :param command: the command, should end with "&"
        :param except_on_error: If True, throw a CommandError exception if
           the command returns a non-zero return code
        :return: (output, exit_code) for the command.
        """
        # Write the command to a temporary shell script, run the script,
        # then delete it.  This seems to be the only reliable way to start
        # a background process without hanging the ssh session.
        temp_filename = str(uuid.uuid4()).split('-')[0] + '.sh'

        self.exec_command(
            'echo "%s" > /tmp/%s' % (command, temp_filename),
            except_on_error=True
        )
        self.exec_command(
            'nohup sh /tmp/%s' % temp_filename,
            except_on_error=except_on_error
        )
        self.exec_command('rm /tmp/%s' % temp_filename, except_on_error=True)

    def get_pty(self, term='console'):
        """
        Create a pseudo terminal on the instance.

        This should be used over exec_command whenever a shell/tty is
        necessary.

        :raises SshError: if the SSH connection has not been
                          established.

        :return: An Paramiko channel to communicate statefully.
        """
        if not self.is_connected():
            raise SshError('Not connected!')

        channel = self.transport.open_session()
        channel.get_pty(term, 80, 24)
        channel.invoke_shell()
        channel.set_combine_stderr(True)
        return channel

    def is_connected(self):
        """
        Check whether SSH connection is established or not.

        :return: True if it is connected; returns False otherwise.
        """
        if self.transport and self.transport.is_active():
            return True
        return False

    def get_ssh_client(self,
                       hostname,
                       username,
                       sock=None,
                       timeout=60,
                       port=22):
        """
        Return an instance of paramiko.

        SSHClient that is connected to the supplied hostname.
        """
        ssh = paramiko.SSHClient()
        ssh.load_system_host_keys("/dev/null")
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        ssh.connect(hostname, username=username, sock=sock,
                    key_filename=self.private_key_path, password=self.password,
                    port=port, timeout=timeout)

        return ssh

    def get_sftp_client(self):
        """Return a paramiko sftp client."""
        if self.sftp_client is None:
            self.connect()
            self.sftp_client = paramiko.SFTPClient.from_transport(
                self.transport)

        return self.sftp_client

    def upload_file(self, source_file, dest_file, timeout=60):
        """SCP upload a file from local host to remote machine."""
        ssh_client = self.get_ssh_client(self.host, self.user, sock=None,
                                         timeout=timeout, port=self.port)

        transport = ssh_client.get_transport()

        with SCPClient(transport) as scp_client:
            scp_client.put(source_file, dest_file)

        transport.close()
        ssh_client.close()

    def download_file(self, source_file, dest_file):
        """SCP download a file from remote host to local host."""
        ssh_client = self.get_ssh_client(self.host, self.user, sock=None,
                                         timeout=60, port=self.port)
        transport = ssh_client.get_transport()

        with SCPClient(transport) as scp_client:
            scp_client.get(source_file, dest_file)

        transport.close()
        ssh_client.close()

    def alt_exec_command(self, cmd, type='ssh', timeout=360, retries=1,
                         raise_on_error=False, username=None):
        """
        Executes the given command by running ssh in a subprocess.
        This is a workaround for an issue with exec_command where
        it times out or crashes, seemingly randomly, in situations where a lot
        of commands are executed in parallel. One situation where this occured
        frequently was running the same benchmark with different
        configurations (in separate processes).
        To summarize: Only use this if you are running into random crashes
        or freezes when ssh:ing in parallel.
        Otherwise, please use exec_command.
        """
        if type != 'ssh':
            raise JammyError("unknown shell")

        username = username or self.user
        host = username + "@" + self.host
        cmd_list = ['ssh', '-tt', '-o', 'StrictHostKeyChecking=no', host, cmd]
        logger.info('Executing Popen ssh command: %s', cmd_list)
        for i in range(retries):
            p = subprocess.Popen(cmd_list, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)

            end_time = time.time() + timeout
            while time.time() < end_time:
                if p.poll() is not None:
                    break
                time.sleep(10)

            exit_status = p.returncode
            output = p.stdout.read()
            if exit_status is None:
                raise CommandTimeout('Command "%s" timed out after %d seconds'
                                     % (cmd, timeout))
            elif exit_status != 0:
                logger.info("error executing `%s`, exit_status %d, "
                            "output: %s", cmd, exit_status, output)
                if i < retries - 1:
                    logger.info("Sleeping for %d seconds before retrying",
                                RETRY_TIMEOUT_S)
                    time.sleep(RETRY_TIMEOUT_S)
            else:
                break

        if raise_on_error:
            assert exit_status == 0, 'output: %s' % (output)

        return output, exit_status

    def alt_exec_background(self, cmd, type='ssh', username=None):
        """
        For when you want to run sudo commands in the background in the guest.

        For all other background running use cases, see exec_background.
        """
        if type != 'ssh':
            raise JammyError("unknown shell")

        (out, xc) = self.exec_command("sudo cat /etc/sudoers")
        if "!requiretty" not in out:
            logging.info(
                "Did not find that requiretty was disabled, disabling!")
            """
            We add a line to /etc/sudoers that allows us to do ssh commands
            without the -tt flag. We do this because the -tt flag messes
            up when we run in the background.

            We add the line by first creating a script that looks like this:
                !#/bin/bash
                printf '\nDefaults\t!requiretty' >> /etc/sudoers
            and then running that script as sudo. We can't run the script as
            sudo without saving it to a file first, because then we get
            blocked by the read-only nature of the /etc/sudoers file.

            The reason the below command looks so extremely convoluted is
            that we first need to break special characters for Python, and
            then also break characters for the shell. We run the script
            and make sure to remove it afterwards.
            """
            self.exec_command(
                "printf \"#\"'!'\"/bin/bash\\nprintf '\\\\\\nDefaults"
                "\\\\\\t\"'!'\"requiretty\\\\\\n' >> /etc/sudoers\\n\""
                " > tmp.sh && sudo sh tmp.sh && rm tmp.sh")

        username = username or self.user
        host = username + "@" + self.host

        cmd = ('sudo -b nohup bash -c "{ %s; } < /dev/null 2>&1 >> '
               'background_output.log"' % cmd)

        cmd_list = ['ssh', '-o', 'StrictHostKeyChecking=no', host, cmd]
        logging.info('Executing Popen ssh command: %s', cmd_list)
        subprocess.Popen(cmd_list, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
