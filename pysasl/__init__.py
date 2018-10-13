# Copyright (c) 2014 Ian C. Good
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

from __future__ import absolute_import

import heapq
from collections import OrderedDict
from functools import total_ordering

from pkg_resources import iter_entry_points

__all__ = ['AuthenticationError', 'UnexpectedAuthChallenge',
           'AuthenticationCredentials',
           'ServerChallenge', 'ServerMechanism',
           'ClientResponse', 'ClientMechanism',
           'SASLAuth']


class AuthenticationError(Exception):
    """Indicates that authentication failed due to a protocol error unrelated
    to any provided credentials.

    """
    pass


class UnexpectedAuthChallenge(AuthenticationError):
    """During client-side authentication, the SASL mechanism received an
    authentication challenge from the server that it did not expect.

    """

    def __init__(self):
        msg = 'Unexpected auth challenge.'
        super(UnexpectedAuthChallenge, self).__init__(msg)


class AuthenticationCredentials(object):
    """Object returned by :meth:`~ServerMechanism.server_attempt` and passed in
    to :meth:`~ClientMechanism.client_attempt` containing information about the
    authentication credentials in use.

    :param authcid: Authentication ID string (the username).
    :param secret: Secret string (the password).
    :param authzid: Authorization ID string, if applicable.

    """

    __slots__ = ['_authcid', '_secret', '_authzid']

    def __init__(self, authcid, secret, authzid=None):
        super(AuthenticationCredentials, self).__init__()
        self._authcid = authcid
        self._secret = secret
        self._authzid = authzid

    @property
    def authcid(self):
        """The authentication identity string used in the attempt."""
        return self._authcid

    @property
    def secret(self):
        """Contains the secret string used in the authentication attempt,
        if available. Use :meth:`.check_secret` instead, when possible.

        """
        return self._secret

    @property
    def authzid(self):
        """The authorization identity string used in the attempt, or ``None``
        if this field is not used by the mechanism.

        """
        return self._authzid

    def check_secret(self, secret):
        """Checks if the secret string used in the authentication attempt
        matches the "known" secret string. Some mechanisms will override this
        method to control how this comparison is made.

        :param secret: The secret string to compare against what was used in
                       the authentication attempt.

        """
        if isinstance(secret, bytes):
            secret = secret.decode('utf-8')
        return secret == self.secret


class ClientResponse(object):
    """Used by :meth:`~ClientMechanism.client_attempt` to provide client
    responses and to populate server challenges.

    """

    __slots__ = ['response', 'challenge']

    def __init__(self, response):
        super(ClientResponse, self).__init__()
        self.response = response
        self.challenge = None

    def get_response(self):
        """Return the client response that should be sent to the server."""
        return self.response

    def set_challenge(self, data):
        """If the server reacts to the response with a challenge, set it with
        this method.

        :param data: The challenge string.

        """
        self.challenge = data


class ServerChallenge(Exception):
    """Raised by :meth:`~ServerMechanism.server_attempt` to provide server
    challenges and to populate client responses.

    """

    __slots__ = ['challenge', 'response']

    def __init__(self, challenge):
        super(ServerChallenge, self).__init__()
        self.challenge = challenge
        self.response = None

    def get_challenge(self):
        """Return the server challenge that should be sent to the client."""
        return self.challenge

    def set_response(self, data):
        """After the challenge is sent to the client, its response should be
        set with this method.

        :param data: The response string.

        """
        self.response = data


@total_ordering
class _BaseMechanism(object):

    @property
    def name(self):
        """The SASL name for this mechanism."""
        raise NotImplementedError()

    @property
    def insecure(self):
        """Whether this mechanism is considered secure for non-encrypted
        sessions. This value should be used to determine which mechanisms are
        exposed.

        """
        return False

    @property
    def priority(self):
        """Determines the sort ordering of this mechanism."""
        return 5

    def __lt__(self, other):
        if not isinstance(other, _BaseMechanism):
            return NotImplemented
        return self.priority < other.priority


class ServerMechanism(_BaseMechanism):
    """Base class for implementing SASL mechanisms that support server-side
    credential verification.

    """

    @property
    def name(self):
        raise NotImplementedError()

    def server_attempt(self, challenges):  # pragma: no cover
        """For SASL server-side credential verification, receives responses
        from the client and issues challenges until it has everything needed to
        verify the credentials.

        If a challenge is necessary, an :class:`ServerChallenge` exception will
        be raised. Send the challenge string to the client with
        :meth:`~ServerChallenge.get_challenge` and then populate its response
        with :meth:`~ServerChallenge.set_response`. Finally, append the
        exception to the ``challenges`` argument before calling again.

        :param challenges: The server challenges that have been issued by
                           the mechanism and responded to by the client.
        :raises: :class:`ServerChallenge`

        """
        raise NotImplementedError()


class ClientMechanism(_BaseMechanism):
    """Base class for implementing SASL mechanisms that support client-side
    credential verification.

    """

    @property
    def name(self):
        raise NotImplementedError()

    def client_attempt(self, creds, responses):  # pragma: no cover
        """For SASL client-side credential verification, produce responses to
        send to the server and react to its challenges until the server returns
        a final success or failure.

        Send the response string to the server with the
        :meth:`~ClientResponse.get_response` method of the returned
        :class:`ClientResponse` object. If the server returns another
        challenge, set it with the object's
        :meth:`~ClientResponse.set_challenge` method and append the object to
        the ``responses`` argument before calling again.

        The mechanism may raise :class:`AuthenticationError` if it receives
        unexpected challenges from the server.

        :param creds: The credentials to attempt authentication with.
        :param responses: The client responses that have been sent to the
                          server. New attempts begin with an empty list.
        :raises: :class:`AuthenticationError`

        """
        raise NotImplementedError()


class SASLAuth(object):
    """Manages the mechanisms available for authentication attempts.

    :param advertised: List of available SASL mechanism objects. Using the
                       name of a built-in mechanism (e.g. ``b'PLAIN'``) works
                       as well. By default, all built-in mechanisms are
                       available.

    """

    __slots__ = ['mechs']

    _known_mechanisms = None

    def __init__(self, advertised=None):
        super(SASLAuth, self).__init__()
        if advertised:
            self.mechs = OrderedDict()
            for mech in advertised:
                if isinstance(mech, _BaseMechanism):
                    self.mechs[mech.name] = mech
                else:
                    known_mechs = self._get_known_mechanisms()
                    self.mechs[mech] = known_mechs[mech]
        else:
            self.mechs = self._get_known_mechanisms()

    @classmethod
    def secure(cls):
        """Uses only authentication mechanisms that are secure for use in
        non-encrypted sessions.

        """
        known_mechs = cls._get_known_mechanisms()
        secure_mechs = [mech for _, mech in known_mechs.items()
                        if not mech.insecure]
        return SASLAuth(secure_mechs)

    @classmethod
    def _get_known_mechanisms(cls):
        if cls._known_mechanisms is None:
            heap = []
            mechs = OrderedDict()
            for entry_point in iter_entry_points('pysasl.mechanisms'):
                mech_cls = entry_point.load()
                heapq.heappush(heap, mech_cls())
            for i in range(len(heap)):
                mech = heapq.heappop(heap)
                mechs[mech.name] = mech
            cls._known_mechanisms = mechs
        return cls._known_mechanisms

    @property
    def server_mechanisms(self):
        """List of available :class:`ServerMechanism` objects."""
        return [mech for mech in self.mechs.values()
                if isinstance(mech, ServerMechanism)]

    @property
    def client_mechanisms(self):
        """List of available :class:`ClientMechanism` objects."""
        return [mech for mech in self.mechs.values()
                if isinstance(mech, ClientMechanism)]

    def get(self, name):
        """Get a SASL mechanism by name. The resulting object should inherit
        either :class:`ServerMechanism`, :class:`ClientMechanism`, or both.

        :param name: The SASL mechanism name.
        :returns: The mechanism object or ``None``

        """
        return self.mechs.get(name.upper())

    def get_server(self, name):
        """Like :meth:`.get`, but only mechanisms inheriting
        :class:`ServerMechanism` will be returned.

        :param name: The SASL mechanism name.
        :returns: The mechanism object or ``None``

        """
        mech = self.get(name)
        return mech if isinstance(mech, ServerMechanism) else None

    def get_client(self, name):
        """Like :meth:`.get`, but only mechanisms inheriting
        :class:`ClientMechanism` will be returned.

        :param name: The SASL mechanism name.
        :returns: The mechanism object or ``None``

        """
        mech = self.get(name)
        return mech if isinstance(mech, ClientMechanism) else None
