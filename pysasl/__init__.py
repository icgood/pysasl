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

from __future__ import absolute_import, unicode_literals

import base64

from pkg_resources import iter_entry_points

__all__ = ['ServerMechanism', 'AuthenticationError', 'IssueChallenge',
           'ChallengeResponse', 'AuthenticationResult']


class AuthenticationError(Exception):
    """Indicates that authentication failed due to a protocol error unrelated
    to any provided credentials.

    """
    pass


class IssueChallenge(Exception):
    """Indicates the server must challenge the client before authentication can
    continue. The :attr:`.challenge` object should have its
    :attr:`~Challengeresponse.response` populated before calling
    :meth:`~ServerMechanism.server_attempt` again.

    """

    def __init__(self, message):
        super(IssueChallenge, self).__init__()

        #: The :class:`ChallengeResponse` object used to track the server's
        #: challenge and the client's response.
        self.challenge = ChallengeResponse(message)


class ChallengeResponse(object):
    """Object used to track and respond to challenges issued by the server and
    the responses from the client.

    Some protocols (e.g. SMTP) allow an initial response from the client,
    before any challenges have been issued::

        initial = AuthenticationChallenge(response='...')

    :param str challenge: The challenge message issued by the server. This
                          value may be ``None`` when building an initial
                          response, used in some protocols.
    :param str response: Pre-populates the :attr:`.response` field.

    """

    def __init__(self, challenge=None, response=None):
        super(ChallengeResponse, self).__init__()

        #: The challenge string issued by the server.
        self.challenge = challenge

        #: The response string from the client.
        self.response = response


class AuthenticationResult(object):
    """Object returned by :meth:`~ServerMechanism.server_attempt` and
    :meth:`~ClientMechanism.client_attempt` containing information and methods
    for checking the result of an authentication attempt.

    """

    def __init__(self, authcid, secret=None, authzid=None):
        super(AuthenticationResult, self).__init__()

        #: The authentication identity string used in the attempt.
        self.authcid = self._decode(authcid)

        #: The authorization identity string used in the attempt, or ``None``
        #: if this field is not used by the mechanism.
        self.authzid = self._decode(authzid)

        #: If available, contains the secret string used in the authentication
        #: attempt, ``None`` otherwise.
        self.secret = self._decode(secret)

    def _decode(self, data):
        if isinstance(data, bytes):
            return data.decode('utf-8')
        return data

    def check_secret(self, secret):
        """Checks if the secret string used in the authentication attempt
        matches the "known" secret string. The way this comparison is made
        depends on the SASL mechanism in use.

        :param str secret: The secret string to compare against what was used
                           in the authentication attempt.
        :rtype: bool

        """
        return self._decode(secret) == self.secret


class ServerMechanism(object):
    """Base class for implementing SASL mechanisms that support server-side
    credential verification.

    .. method:: server_attempt(self, responses)

       For SASL server-side credential verification, receives responses from
       the client and issues challenges until it has everything needed to
       verify the credentials.

       :param list responses: The list of :class:`ChallengeResponse` objects
                              that have been issued by the mechanism and
                              responded to by the client.
       :raises: :class:`IssueChallenge`
       :rtype: :class:`AuthenticationResult`

    """

    @classmethod
    def get_available(cls, allow_insecure=False):
        """Returns a mapping of mechanism names to :class:`ServerMechanism`
        sub-classes that meet the criteria. The name is the uppercase SASL
        name, e.g. ``PLAIN``.

        :param bool allow_insecure: Usually this will be ``False`` unless the
                                    connection has been TLS encrypted.
        :rtype: dict

        """
        ret = {}
        for entry_point in iter_entry_points('pysasl.mechanisms'):
            mech = entry_point.load()
            if not allow_insecure and getattr(mech, 'insecure', False):
                continue
            ret[mech.name] = mech
        return ret
