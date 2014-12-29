
from __future__ import absolute_import

import unittest

from pysasl import (ServerMechanism, IssueChallenge, ChallengeResponse,
    AuthenticationError)
from pysasl.login import LoginMechanism


class TestLoginMechanism(unittest.TestCase):

    def setUp(self):
        self.login = LoginMechanism()

    def test_available(self):
        avail = ServerMechanism.get_available(True)
        self.assertEqual(LoginMechanism, avail.get('LOGIN'))

    def test_issues_challenges(self):
        try:
            self.login.server_attempt([])
        except IssueChallenge as exc:
            self.assertEqual('Username:', exc.challenge.challenge)
        else:
            self.fail('first IssueChallenge not raised')
        try:
            self.login.server_attempt(['test'])
        except IssueChallenge as exc:
            self.assertEqual('Password:', exc.challenge.challenge)
        else:
            self.fail('second IssueChallenge not raised')

    def test_successful(self):
        resp1 = ChallengeResponse(response='testuser')
        resp2 = ChallengeResponse(response='testpass')
        result = self.login.server_attempt([resp1, resp2])
        self.assertTrue(result.authzid is None)
        self.assertEqual('testuser', result.authcid)
        self.assertTrue(result.check_secret('testpass'))
