
from __future__ import absolute_import

import unittest

from pysasl import ServerChallenge
from pysasl.login import LoginMechanism


class TestLoginMechanism(unittest.TestCase):

    def setUp(self):
        self.login = LoginMechanism()

    def test_issues_challenges(self):
        try:
            self.login.server_attempt([])
        except ServerChallenge as exc:
            self.assertEqual(b'Username:', exc.challenge)
        else:
            self.fail('first ServerChallenge not raised')
        try:
            self.login.server_attempt(['test'])
        except ServerChallenge as exc:
            self.assertEqual(b'Password:', exc.challenge)
        else:
            self.fail('second ServerChallenge not raised')

    def test_successful(self):
        resp1 = ServerChallenge(b'Username:')
        resp1.set_response(b'testuser')
        resp2 = ServerChallenge(b'Password:')
        resp2.set_response(b'testpass')
        result = self.login.server_attempt([resp1, resp2])
        self.assertTrue(result.authzid is None)
        self.assertEqual('testuser', result.authcid)
        self.assertTrue(result.check_secret('testpass'))
