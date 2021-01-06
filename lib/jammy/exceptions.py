import logging

logger = logging.getLogger(__name__)


class JammyError(Exception):
    """
    Base class for all Jammy errors.
    """
    pass


class DeprecationError(JammyError):
    """
    Indicates a method has been deprecated with no replacement.
    """

    pass


class SshError(JammyError):
    """
    Indicates a problem with SSH.
    """

    pass


class CommandError(JammyError):
    """
    Indicates a command completed, but failed
    """

    pass


class CommandTimeout(JammyError):
    """
    Indicates a command timed out
    """

    pass


class MethodTimeout(JammyError):
    """
    Indicates a method timed out
    """

    pass


class NotAuthenticatedError(JammyError):
    """
    Indicates the user isn't authenticated to perform this action
    """

    pass


class ApiResponseError(JammyError):
    """
    Indicats a REST API error
    """

    def __init__(self, response):
        message = "status: {0}\nreason: {1}\nerror: {2}".format(
            response.response.status_code,
            response.response.reason,
            response.response.text)
        # Call the base class constructor with the parameters it needs
        super(ApiResponseError, self).__init__(message)
