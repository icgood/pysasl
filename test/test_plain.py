
from __future__ import absolute_import

import unittest

from pysasl import (ServerMechanism, IssueChallenge, ChallengeResponse,
    AuthenticationError)
from pysasl.plain import PlainMechanism


class TestPlainMechanism(unittest.TestCase):

    def setUp(self):
        self.plain = PlainMechanism()

    def test_available(self):
        avail = ServerMechanism.get_available(True)
        self.assertEqual(PlainMechanism, avail.get('PLAIN'))

    def test_issues_challenge(self):
        try:
            self.plain.server_attempt([])
        except IssueChallenge as exc:
            self.assertEqual('', exc.challenge.challenge)
        else:
            self.fail('IssueChallenge not raised')

    def test_bad_response(self):
        resp = ChallengeResponse(response='abcdefghi')
        self.assertRaises(AuthenticationError,
                          self.plain.server_attempt, [resp])

    def test_successful(self):
        resp = ChallengeResponse(response='abc\x00def\x00ghi')
        result = self.plain.server_attempt([resp])
        self.assertEqual('abc', result.authzid)
        self.assertEqual('def', result.authcid)
        self.assertTrue(result.check_secret('ghi'))
