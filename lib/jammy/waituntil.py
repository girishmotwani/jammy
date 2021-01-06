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

    Useful for retrying flaky Azure calls.
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
