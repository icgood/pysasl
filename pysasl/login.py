from __future__ import absolute_import

from . import (ServerMechanism, ClientMechanism, ServerChallenge,
               ClientResponse, AuthenticationCredentials,
               UnexpectedAuthChallenge)

__all__ = ['LoginMechanism']


class LoginMechanism(ServerMechanism, ClientMechanism):
    """Implements the LOGIN authentication mechanism.

    Attributes:
        name: The SASL name for this mechanism.
        priority: Determines the sort ordering of this mechanism.
        insecure: This mechanism is not considered secure for non-encrypted
            sessions.

    """

    name = b'LOGIN'
    priority = 5
    insecure = True

    def server_attempt(self, challenges):
        if len(challenges) < 1:
            raise ServerChallenge(b'Username:')
        if len(challenges) < 2:
            raise ServerChallenge(b'Password:')
        username = challenges[0].response.decode('utf-8')
        password = challenges[1].response.decode('utf-8')
        return AuthenticationCredentials(username, password)

    def client_attempt(self, creds, responses):
        if len(responses) < 1:
            return ClientResponse(b'')
        if len(responses) < 2:
            username = creds.authcid.encode('utf-8')
            return ClientResponse(username)
        if len(responses) < 3:
            password = creds.secret.encode('utf-8')
            return ClientResponse(password)
        raise UnexpectedAuthChallenge()
