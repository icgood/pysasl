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

from pkg_resources import iter_entry_points

__all__ = ['ServerMechanism', 'IssueServerChallenge', 'VerifySecret']


class IssueServerChallenge(Exception):
    """Indicates the server must challenge the client before authentication can
    continue. The :meth:`~ServerMechanism.server_attempt` method should then be
    called again with an additional string in the ``responses`` parameter.

    """

    def __init__(self, challenge):
        super(IssueServerChallenge, self).__init__()

        #: The un-encoded challenge string that should be sent to the client.
        self.challenge = challenge


class VerifySecret(Exception):
    """Indicates the credentials must be verified by passing the user's secret
    (i.e. password) to the given function. It will return True or False if the
    given secret matches what was given by the client.

    This is only necessary for mechanisms that require 

    """

    def __init__(self, username, callback):
        super(RetryWithSecret, self).__init__()

        #: The username to lookup the secret credential for.
        self.username = username


class ServerMechanism(object):
    """Base class for implementing SASL mechanisms that support server-side
    credential verification.

    .. method:: server_attempt(self, responses, secret=None)

       For SASL server-side credential verification, receives responses from
       the client and issues challenges until it has everything needed to
       verify the credentials. In some mechanisms, the command may need to be
       re-issued with the user's ``secret`` (i.e. password) to compare with
       what it received from the client.

       :param list responses: The list of responses that have been received
                              from the client.
       :param str secret: The user's password to be compared with what was
                          received from the client, needed for some mechanisms.
       :raises: :class:`RetryWithChallengeResponse`, :class:`RetryWithSecret`
       :returns: 

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
        for mech in iter_entry_points('pysasl.mechanisms'):
            if not allow_insecure and getattr(mech, 'insecure', False):
                continue
            ret[mech.name] = mech
        return ret
