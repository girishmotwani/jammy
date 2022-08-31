"""Common utility functions for usage in Jammy."""

import datetime
import logging
import time

logger = logging.getLogger(__name__)

DEFAULT_PERIOD = 20.0  # 20 seconds
DEFAULT_TIMEOUT = 10 * 60.0  # 10 minutes


def waituntil(condition, timeout_in_seconds,
              period_in_seconds=DEFAULT_PERIOD, raise_on_timeout=False):
    """Wait until some condition is met."""
    end_time = time.time() + timeout_in_seconds

    while time.time() < end_time:
        try:
            if condition():
                return True
        except:
            pass
        time.sleep(period_in_seconds)

    if raise_on_timeout:
        raise RuntimeError("Condition was never met")
    return False


def retry_on_exception(func, num_tries=40, period_in_seconds=DEFAULT_PERIOD,
                       error=None):
    """
    Retry function until there is no error or exception.

    Useful for retrying flaky EC2 boto calls.
    """
    for x in range(num_tries):
        try:
            return func()
        except Exception as e:
            if error and e.error_code == error:
                logging.info("Skipping on exception %s" % error)
                break
            if x == (num_tries - 1):
                raise RuntimeError("Failed on %d tries: %s" % (num_tries, e))
            logging.info("Got exception %s on try number %s..." % (e, x))

        time.sleep(period_in_seconds)


# TODO: This is AWS-specific...
def verify_running_instance(instance, timeout_in_seconds=DEFAULT_TIMEOUT):
    """
    We need to re-start the instance in the case it stops.

    See bug NUC-9891 for detailed information.
    """
    inst = instance.csp_instance
    end_time = time.time() + timeout_in_seconds

    while inst.update() != 'running' and time.time() < end_time:
        if waituntil(lambda: inst.update() != 'pending', 300):
            if inst.update() == 'stopped':
                inst.start()

    return inst.update() == 'running'


def _can_connect(instance, usernames):
    for username in usernames:
        instance.username = username
        instance.disconnect()
        try:
            # Write out current timestamp
            cmd = 'echo "is sshable at time %s"' % get_iso_timestamp()
            response, exit_status = instance.exec_command(cmd, timeout=60)
            return exit_status == 0
        except Exception as e:
            # re-raise filedescriptor errors since these are indicative of
            # errors in the test suite (NUC-10929)
            if "filedescriptor" in str(e):
                raise
            logging.debug(str(e))
    return False


def is_sshable(instance, timeout_in_seconds=DEFAULT_TIMEOUT, usernames=None):
    """
    Poke an instance to see if it can be SSH'd to by trying to run a command.
    In the trial SSH command, we write out the current timestamp to a file to
    make sure the filesystem isn't borked.

    Rotates on different possible usernames.

    :param instance: an instance object
    """
    if instance.dst_port == 22 and usernames is None:
        usernames = ['ec2-user',
                     'ubuntu',
                     'centos']
    elif instance.dst_port == 122:
        usernames = ['avatar']

    if instance.username:
        usernames = [instance.username]

    end_time = time.time() + timeout_in_seconds

    logger.info('Attempting to SSH into instance\n')

    while time.time() < end_time:
        if _can_connect(instance, usernames):
            return True

        time.sleep(DEFAULT_PERIOD)

    # Do one last check because sometimes the above loop freezes in the
    # and then this function fails even though guest is sshable
    return _can_connect(instance, usernames)


def is_in_response(instance, command, str):
    """
    Execute an SSH command and look for a specified string in the response.

    ::param command:: the command string
    ::param str:: the string you are looking for in the response
    """
    try:
        response, _ = instance.exec_command(command)
        return str in response
    except:
        return False


def get_iso_timestamp(duration_in_minutes=60):
    """Return an ISO timestamp needed in making certain requests to the API."""
    now = datetime.datetime.utcnow()
    timestamp = now + datetime.timedelta(minutes=duration_in_minutes)
    return timestamp.isoformat() + '+00:00'
