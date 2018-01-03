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

    :param str authcid: Authentication ID string (the username).
    :param str secret: Secret string (the password).
    :param str authzid: Authorization ID string, if applicable.

    .. attribute:: authcid

       The authentication identity string used in the attempt.

    .. attribute:: secret

       If available, contains the secret string used in the authentication
       attempt, ``None`` otherwise.

    .. attribute:: authzid

       The authorization identity string used in the attempt, or ``None`` if
       this field is not used by the mechanism.

    """

    __slots__ = ['authcid', 'secret', 'authzid']

    def __init__(self, authcid, secret, authzid=None):
        super(AuthenticationCredentials, self).__init__()
        self.authcid = authcid
        self.secret = secret
        self.authzid = authzid

    def check_secret(self, secret):
        """Checks if the secret string used in the authentication attempt
        matches the "known" secret string. Some mechanisms will override this
        method to control how this comparison is made.

        :param str secret: The secret string to compare against what was used
                           in the authentication attempt.
        :rtype: bool

        """
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
        """Return the client response that should be sent to the server.

        :rtype: bytes

        """
        return self.response

    def set_challenge(self, data):
        """If the server reacts to the response with a challenge, set it with
        this method.

        :param bytes data: The challenge string.

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
        """Return the server challenge that should be sent to the client.

        :rtype: bytes

        """
        return self.challenge

    def set_response(self, data):
        """After the challenge is sent to the client, its response should be
        set with this method.

        :param bytes data: The response string.

        """
        self.response = data


@total_ordering
class _BaseMechanism(object):

    def __init__(self, name=None):
        super(_BaseMechanism, self).__init__()
        if name is not None:
            self.name = name

    def __lt__(self, other):
        if not isinstance(other, _BaseMechanism):
            return NotImplemented
        my_priority = getattr(self, '_priority', 5)
        other_priority = getattr(other, '_priority', 5)
        return my_priority < other_priority


class ServerMechanism(_BaseMechanism):
    """Base class for implementing SASL mechanisms that support server-side
    credential verification.

    :param str name: Override the standard SASL mechanism name.

    """

    def server_attempt(self, challenges):  # pragma: no cover
        """For SASL server-side credential verification, receives responses
        from the client and issues challenges until it has everything needed to
        verify the credentials.

        If a challenge is necessary, an :class:`ServerChallenge` exception will
        be raised. Send the challenge string to the client with
        :meth:`~ServerChallenge.get_challenge` and then populate its response
        with :meth:`~ServerChallenge.set_response`. Finally, append the
        exception to the ``challenges`` argument before calling again.

        :param list challenges: The list of :class:`ServerChallenge` objects
                                that have been issued by the mechanism and
                                responded to by the client.
        :raises: :class:`ServerChallenge`
        :rtype: :class:`AuthenticationCredentials`

        """
        raise NotImplementedError()


class ClientMechanism(_BaseMechanism):
    """Base class for implementing SASL mechanisms that support client-side
    credential verification.

    """

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
        :type creds: :class:`AuthenticationCredentials`
        :param list responses: The list of :class:`ClientResponse` objects that
                               have been sent to the server. New attempts begin
                               with an empty list.
        :rtype: :class:`ChallengeResponse`
        :raises: :class:`AuthenticationError`

        """
        raise NotImplementedError()


class SASLAuth(object):
    """Manages the mechanisms available for authentication attempts.

    :param list advertised: List of available SASL mechanism objects. Using the
                            name of a built-in mechanism (e.g. ``b'PLAIN'``)
                            works as well. By default, all built-in mechanisms
                            are available.

    """

    __slots__ = ['mechs']

    def __init__(self, advertised=None):
        super(SASLAuth, self).__init__()
        known_mechs = self._load_known_mechanisms()
        if advertised:
            self.mechs = OrderedDict()
            for mech in advertised:
                if isinstance(mech, _BaseMechanism):
                    self.mechs[mech.name] = mech
                else:
                    self.mechs[mech] = known_mechs[mech]
        else:
            self.mechs = known_mechs

    @classmethod
    def _load_known_mechanisms(cls):
        heap = []
        mechs = OrderedDict()
        for entry_point in iter_entry_points('pysasl.mechanisms'):
            mech_cls = entry_point.load()
            heapq.heappush(heap, mech_cls())
        for i in range(len(heap)):
            mech = heapq.heappop(heap)
            mechs[mech.name] = mech
        return mechs

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

        :param bytes name: The SASL mechanism name.
        :returns: The mechanism object or ``None``

        """
        return self.mechs.get(name.upper())
