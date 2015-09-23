
from __future__ import absolute_import

import unittest

from pysasl import ServerChallenge, AuthenticationError
from pysasl.plain import PlainMechanism


class TestPlainMechanism(unittest.TestCase):

    def setUp(self):
        self.plain = PlainMechanism()

    def test_issues_challenge(self):
        try:
            self.plain.server_attempt([])
        except ServerChallenge as exc:
            self.assertEqual(b'', exc.challenge)
        else:
            self.fail('ServerChallenge not raised')

    def test_bad_response(self):
        resp = ServerChallenge(b'')
        resp.set_response(b'abcdefghi')
        self.assertRaises(AuthenticationError,
                          self.plain.server_attempt, [resp])

    def test_successful(self):
        resp = ServerChallenge(b'')
        resp.set_response(b'abc\x00def\x00ghi')
        result = self.plain.server_attempt([resp])
        self.assertEqual('abc', result.authzid)
        self.assertEqual('def', result.authcid)
        self.assertTrue(result.check_secret('ghi'))
