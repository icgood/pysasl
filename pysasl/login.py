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

from . import ServerMechanism, IssueChallenge, AuthenticationResult

__all__ = ['LoginMechanism']


class LoginMechanism(ServerMechanism):
    """Implements the LOGIN authentication mechanism.

    """

    #: The SASL name for this mechanism.
    name = 'LOGIN'

    #: This mechanism is considered insecure for non-encrypted sessions.
    insecure = True

    def server_attempt(self, responses, **kwargs):
        if len(responses) < 1:
            raise IssueChallenge('Username:')
        if len(responses) < 2:
            raise IssueChallenge('Password:')
        username = responses[0].response
        password = responses[1].response
        return AuthenticationResult(username, password)
