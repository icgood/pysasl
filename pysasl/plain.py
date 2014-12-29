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

import re

from . import (ServerMechanism, IssueChallenge,
    AuthenticationError, AuthenticationResult)

__all__ = ['PlainMechanism']


class PlainMechanism(ServerMechanism):
    """Implements the PLAIN authentication mechanism.

    """

    #: The SASL name for this mechanism.
    name = 'PLAIN'

    #: This mechanism is considered insecure for non-encrypted sessions.
    insecure = True

    _pattern = re.compile(r'^([^\x00]*)\x00([^\x00]+)\x00([^\x00]*)$')

    def server_attempt(self, responses):
        if not responses:
            raise IssueChallenge('')

        response = responses[0].response
        match = self._pattern.match(response)
        if not match:
            raise AuthenticationError('Invalid PLAIN response')
        zid, cid, secret = match.groups()

        return AuthenticationResult(cid, secret, zid)
