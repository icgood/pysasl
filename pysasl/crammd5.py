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
import time
import uuid
import hmac
import hashlib
from socket import gethostname

from . import (ServerMechanism, IssueChallenge,
    AuthenticationError, AuthenticationResult)

__all__ = ['CramMD5Mechanism']


class CramMD5Result(AuthenticationResult):

    def __init__(self, username, challenge, digest):
        super(CramMD5Result, self).__init__(username)
        self.challenge = challenge
        self.digest = digest.encode('ascii')

    def check_secret(self, secret):
        if isinstance(secret, str):
            secret = secret.encode('utf-8')
        challenge = self.challenge.encode('utf-8')
        expected = hmac.new(secret, challenge, hashlib.md5).hexdigest()
        return expected.encode('ascii') == self.digest


class CramMD5Mechanism(ServerMechanism):
    """Implements the CRAM-MD5 authentication mechanism.

    .. warning::

       Offering this mechanism can be dangerous, as it usually means that
       credentials are stored in clear-text.

    """

    #: The SASL name for this mechanism.
    name = 'CRAM-MD5'

    #: This mechanism is considered secure for non-encrypted sessions.
    insecure = False

    #: Unless this class-level attribute is set, :py:func:`~socket.gethostname`
    #: will be used when generating challenge strings.
    hostname = None

    _pattern = re.compile(r'^(.*) ([^ ]+)$')

    def __init__(self):
        super(CramMD5Mechanism, self).__init__()
        if self.hostname is None:
            self.hostname = gethostname()

    def _build_challenge(self):
        uid = uuid.uuid4().hex
        timestamp = time.time()
        return'<{0}.{1:.0f}@{2}>'.format(uid, timestamp, self.hostname)

    def server_attempt(self, responses):
        if not responses:
            raise IssueChallenge(self._build_challenge())
        challenge = responses[0].challenge
        response = responses[0].response

        match = self._pattern.match(response)
        if not match:
            raise AuthenticationError('Invalid CRAM-MD5 response')
        username, digest = match.groups()

        return CramMD5Result(username, challenge, digest)
