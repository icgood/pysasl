from __future__ import absolute_import

import re
import hmac
import hashlib
import email.utils

from . import (ServerMechanism, ClientMechanism, ServerChallenge,
               ClientResponse, AuthenticationError, UnexpectedAuthChallenge,
               AuthenticationCredentials)

__all__ = ['CramMD5Result', 'CramMD5Mechanism']


class CramMD5Result(AuthenticationCredentials):
    """Because this mechanism uses hash algorithms to compare secrets, the
    :meth:`~CramMD5Mechanism.server_attempt` method returns this sub-class
    which overrides the :meth:`.check_secret` method.

    Attributes:
        challenge: The challenge string issued by the server.
        digest: The digest computed by the client.

    """

    __slots__ = ['challenge', 'digest']

    def __init__(self, username, challenge, digest):
        super(CramMD5Result, self).__init__(username, '')
        self.challenge = challenge
        self.digest = digest

    @property
    def secret(self):
        """The secret string is not available in this mechanism.

        Raises:
            NotImplementedError

        """
        raise NotImplementedError()

    def check_secret(self, secret):
        if not isinstance(secret, bytes):
            secret = secret.encode('utf-8')
        expected_hmac = hmac.new(secret, self.challenge, hashlib.md5)
        expected = expected_hmac.hexdigest().encode('ascii')
        try:
            return hmac.compare_digest(expected, self.digest)
        except AttributeError:  # pragma: no cover
            return expected == self.digest


class CramMD5Mechanism(ServerMechanism, ClientMechanism):
    """Implements the CRAM-MD5 authentication mechanism.

    Warning:
        Although secure during transport, offering this mechanism can be
        dangerous, as it can have implications about how the credentials are
        stored server-side.

    Attributes:
        name: The SASL name for this mechanism.
        priority: Determines the sort ordering of this mechanism.
        insecure: This mechanism is considered secure for non-encrypted
            sessions.

    """

    _pattern = re.compile(br'^(.*) ([^ ]+)$')

    name = b'CRAM-MD5'
    priority = 10
    insecure = False

    def server_attempt(self, challenges):
        if not challenges:
            challenge = email.utils.make_msgid().encode('utf-8')
            raise ServerChallenge(challenge)
        challenge = challenges[0].challenge
        response = challenges[0].response

        match = re.match(self._pattern, response)
        if not match:
            raise AuthenticationError('Invalid CRAM-MD5 response')
        username, digest = match.groups()

        username_str = username.decode('utf-8')
        return CramMD5Result(username_str, challenge, digest)

    def client_attempt(self, creds, responses):
        if len(responses) < 1:
            return ClientResponse(b'')
        elif len(responses) > 1:
            raise UnexpectedAuthChallenge()
        challenge = responses[0].challenge
        authcid = creds.authcid.encode('utf-8')
        secret = creds.secret.encode('utf-8')
        digest = hmac.new(secret, challenge, hashlib.md5).hexdigest()
        response = b' '.join((authcid, digest.encode('ascii')))
        return ClientResponse(response)
