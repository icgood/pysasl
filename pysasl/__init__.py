from __future__ import absolute_import

import heapq
from collections import OrderedDict
from functools import total_ordering

from pkg_resources import iter_entry_points

__all__ = ['AuthenticationError', 'UnexpectedAuthChallenge',
           'AuthenticationCredentials', 'BaseMechanism',
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

    Args:
        authcid: Authentication ID string (the username).
        secret: Secret string (the password).
        authzid: Authorization ID string, if applicable.

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

        Args:
            secret: The secret string to compare against what was used in the
                authentication attempt.

        Returns:
            True if the given secret matches the authentication attempt.

        """
        if isinstance(secret, bytes):
            secret = secret.decode('utf-8')
        return secret == self.secret


class ClientResponse(object):
    """Used by :meth:`~ClientMechanism.client_attempt` to provide client
    responses and to populate server challenges.

    Args:
        response: The response string that should be sent to the server.

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

        Args:
            data: The challenge string.

        """
        self.challenge = data


class ServerChallenge(Exception):
    """Raised by :meth:`~ServerMechanism.server_attempt` to provide server
    challenges and to populate client responses.

    Args:
        challenge: The challenge string that should be sent to the client.

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

        Args:
            data: The response string.

        """
        self.response = data


@total_ordering
class BaseMechanism(object):
    """Base class for all server- and client-side SASL mechanisms.

    Attributes:
        name: The SASL name for this mechanism.
        priority: Determines the sort ordering of this mechanism.
        insecure: Whether this mechanism is considered secure for non-encrypted
            sessions. This value should be used by implementations to determine
            which mechanisms are chosen or offered.

    """

    name = b''
    priority = None
    insecure = False

    def __lt__(self, other):
        if not isinstance(other, BaseMechanism):
            return NotImplemented
        elif other.priority is None:
            return False
        elif self.priority is None:
            return True
        else:
            return self.priority < other.priority


class ServerMechanism(BaseMechanism):
    """Base class for implementing SASL mechanisms that support server-side
    credential verification.

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

        Args:
            challenges: The server challenges that have been issued by the
                mechanism and responded to by the client.

        Returns:
            The authentication credentials received from the client once no
            more challenges are necessary.

        Raises:
            ServerChallenge: The server challenge needing a client response.

        """
        raise NotImplementedError()


class ClientMechanism(BaseMechanism):
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

        Args:
            creds: The credentials to attempt authentication with.
            responses: The client responses that have been sent to the server.
                New attempts begin with an empty list.

        Returns:
            The client response to the most recent server challenge.

        Raises:
            UnexpectedAuthChallenge: The server has issued an unexpected
                challenge the client mechanism does not recognize.

        """
        raise NotImplementedError()


class SASLAuth(object):
    """Manages the mechanisms available for authentication attempts.

    Args:
        advertised: List of available SASL mechanism objects. Using the name
            of a built-in mechanism (e.g. ``b'PLAIN'``) works as well. By
            default, all built-in mechanisms are available.

    """

    __slots__ = ['mechs']

    _builtin_mechanisms = None

    def __init__(self, advertised=None):
        super(SASLAuth, self).__init__()
        if not advertised:
            builtin_mechs = self._get_builtin_mechanisms()
            advertised = [mech for mech in builtin_mechs.values()
                          if mech.priority is not None]
        self.mechs = OrderedDict()
        for mech in advertised:
            if isinstance(mech, BaseMechanism):
                self.mechs[mech.name] = mech
            else:
                builtin_mechs = self._get_builtin_mechanisms()
                self.mechs[mech] = builtin_mechs[mech]

    @classmethod
    def secure(cls):
        """Uses only authentication mechanisms that are secure for use in
        non-encrypted sessions.

        Returns:
            A new :class:`SASLAuth` object.

        """
        builtin_mechs = cls._get_builtin_mechanisms()
        secure_mechs = [mech for _, mech in builtin_mechs.items()
                        if not mech.insecure and mech.priority is not None]
        return SASLAuth(secure_mechs)

    @classmethod
    def _get_builtin_mechanisms(cls):
        if cls._builtin_mechanisms is None:
            heap = []
            mechs = OrderedDict()
            for entry_point in iter_entry_points('pysasl.mechanisms'):
                mech_cls = entry_point.load()
                heapq.heappush(heap, mech_cls())
            for i in range(len(heap)):
                mech = heapq.heappop(heap)
                mechs[mech.name] = mech
            cls._builtin_mechanisms = mechs
        return cls._builtin_mechanisms

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

        Args:
            name: The SASL mechanism name.

        Returns:
            The mechanism object or ``None``

        """
        return self.mechs.get(name.upper())

    def get_server(self, name):
        """Like :meth:`.get`, but only mechanisms inheriting
        :class:`ServerMechanism` will be returned.

        Args:
            name: The SASL mechanism name.

        Returns:
            The mechanism object or ``None``

        """
        mech = self.get(name)
        return mech if isinstance(mech, ServerMechanism) else None

    def get_client(self, name):
        """Like :meth:`.get`, but only mechanisms inheriting
        :class:`ClientMechanism` will be returned.

        Args:
            name: The SASL mechanism name.

        Returns:
            The mechanism object or ``None``

        """
        mech = self.get(name)
        return mech if isinstance(mech, ClientMechanism) else None
