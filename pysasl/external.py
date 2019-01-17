from __future__ import absolute_import

from . import (ServerMechanism, ClientMechanism, ServerChallenge,
               ClientResponse, AuthenticationCredentials,
               UnexpectedAuthChallenge)

__all__ = ['ExternalResult', 'ExternalMechanism']


class ExternalResult(AuthenticationCredentials):
    """Because this mechanism does not use authentication identity or secret
    strings, the :meth:`~ExternalMechanism.server_attempt` method returns this
    sub-class which only allows the :attr:`.authzid` attribute.

    """

    def __init__(self, authzid=None):
        super(ExternalResult, self).__init__('', '', authzid)

    @property
    def has_secret(self):
        return False

    @property
    def authcid(self):
        """The authentication identity string is an alias of the
        :attr:`.authzid` string for this mechanism, except it will return an
        empty string instead of ``None``.

        """
        return self.authzid or ''

    @property
    def secret(self):
        """The secret string is not available for this mechanism.

        Raises:
            AttributeError

        """
        raise AttributeError('secret')

    def check_secret(self, secret):
        """This method always returns True for this mechanism, unless
        overridden by a subclass to provide external enforcement rules.

        """
        return True


class ExternalMechanism(ServerMechanism, ClientMechanism):
    """Implements the EXTERNAL authentication mechanism.

    See Also:
        `RFC 4422 Appendix A <https://tools.ietf.org/html/rfc4422#appendix-A>`_

    Attributes:
        name: The SASL name for this mechanism.
        priority: Determines the sort ordering of this mechanism.
        insecure: This mechanism is considered secure for non-encrypted
            sessions.

    """

    name = b'EXTERNAL'
    priority = None
    insecure = False

    def server_attempt(self, challenges):
        if not challenges:
            raise ServerChallenge(b'')
        authzid = challenges[0].response
        authzid_str = authzid.decode('utf-8')
        return ExternalResult(authzid_str)

    def client_attempt(self, creds, responses):
        if len(responses) > 1:
            raise UnexpectedAuthChallenge()
        authzid = (creds.authzid or '').encode('utf-8')
        return ClientResponse(authzid)
