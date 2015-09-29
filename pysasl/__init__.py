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
    :param str secret: Secret secret (the password).
    :param str authzid: Authorization ID string, if applicable.

    """

    def __init__(self, authcid, secret, authzid=None):
        super(AuthenticationCredentials, self).__init__()

        #: The authentication identity string used in the attempt.
        self.authcid = authcid

        #: If available, contains the secret string used in the authentication
        #: attempt, ``None`` otherwise.
        self.secret = secret

        #: The authorization identity string used in the attempt, or ``None``
        #: if this field is not used by the mechanism.
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


class ServerMechanism(object):
    """Base class for implementing SASL mechanisms that support server-side
    credential verification.

    .. classmethod:: server_attempt(self, challenges)

       For SASL server-side credential verification, receives responses from
       the client and issues challenges until it has everything needed to
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
    pass


class ClientMechanism(object):
    """Base class for implementing SASL mechanisms that support client-side
    credential verification.

    .. classmethod:: client_attempt(self, creds, responses)

       For SASL client-side credential verification, produce responses to send
       to the server and react to its challenges until the server returns a
       final success or failure.

       Send the response string to the server with the
       :meth:`~ClientResponse.get_response` method of the returned
       :class:`ClientResponse` object. If the server returns another challenge,
       set it with the object's :meth:`~ClientResponse.set_challenge` method
       and append the object to the ``responses`` argument before calling
       again.

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
    pass


class SASLAuth(object):
    """Manages the mechanisms available for authentication attempts.

    :param list advertised: List of SASL mechanism name strings. The set of
                            known mechanisms will be intersected with these
                            names. By default, all known mechanisms are
                            available.

    """

    def __init__(self, advertised=None):
        super(SASLAuth, self).__init__()
        self.mechs = self._load_known_mechanisms()
        if advertised:
            advertised = set(advertised)
            self.mechs = dict([(name, mech)
                               for name, mech in self.mechs.items()
                               if name in advertised])

    @classmethod
    def _load_known_mechanisms(cls):
        mechs = {}
        for entry_point in iter_entry_points('pysasl.mechanisms'):
            mech = entry_point.load()
            mechs[mech.name] = mech
        return mechs

    @property
    def server_mechanisms(self):
        """List of available :class:`ServerMechanism` classes."""
        return [mech for mech in self.mechs.values()
                if hasattr(mech, 'server_attempt')]

    @property
    def client_mechanisms(self):
        """List of available :class:`ClientMechanism` classes."""
        return [mech for mech in self.mechs.values()
                if hasattr(mech, 'client_attempt')]

    def get(self, name):
        """Get a SASL mechanism by name. The resulting class should support
        either :meth:`~ServerMechanism.server_attempt`,
        :meth:`~ClientMechanism.client_attempt` or both.

        :param bytes name: The SASL mechanism name.
        :returns: The mechanism class or ``None``

        """
        return self.mechs.get(name.upper())
