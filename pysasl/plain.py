from __future__ import absolute_import

import re

from . import (ServerMechanism, ClientMechanism, ServerChallenge,
               ClientResponse, AuthenticationError, AuthenticationCredentials,
               UnexpectedAuthChallenge)

__all__ = ['PlainMechanism']


class PlainMechanism(ServerMechanism, ClientMechanism):
    """Implements the PLAIN authentication mechanism.

    Attributes:
        name: The SASL name for this mechanism.
        priority: Determines the sort ordering of this mechanism.
        insecure: This mechanism is not considered secure for non-encrypted
            sessions.

    """

    _pattern = re.compile(br'^([^\x00]*)\x00([^\x00]+)\x00([^\x00]*)$')

    name = b'PLAIN'
    priority = 1
    insecure = True

    def server_attempt(self, challenges):
        if not challenges:
            raise ServerChallenge(b'')

        response = challenges[0].response
        match = re.match(self._pattern, response)
        if not match:
            raise AuthenticationError('Invalid PLAIN response')
        zid, cid, secret = match.groups()

        cid_str = cid.decode('utf-8')
        secret_str = secret.decode('utf-8')
        zid_str = zid.decode('utf-8')
        return AuthenticationCredentials(cid_str, secret_str, zid_str)

    def client_attempt(self, creds, responses):
        if len(responses) > 1:
            raise UnexpectedAuthChallenge()
        authzid = (creds.authzid or '').encode('utf-8')
        authcid = creds.authcid.encode('utf-8')
        secret = creds.secret.encode('utf-8')
        response = b'\0'.join((authzid, authcid, secret))
        return ClientResponse(response)
