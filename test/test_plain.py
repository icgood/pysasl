
from __future__ import absolute_import

import unittest

from pysasl import (SASLAuth, ServerChallenge, AuthenticationError,
                    UnexpectedAuthChallenge, AuthenticationCredentials)
from pysasl.plain import PlainMechanism


class TestPlainMechanism(unittest.TestCase):

    def test_availability(self):
        sasl = SASLAuth([b'PLAIN'])
        self.assertEqual([PlainMechanism], sasl.client_mechanisms)
        self.assertEqual([PlainMechanism], sasl.server_mechanisms)
        self.assertEqual(PlainMechanism, sasl.get(b'PLAIN'))

    def test_server_attempt_issues_challenge(self):
        try:
            PlainMechanism.server_attempt([])
        except ServerChallenge as exc:
            self.assertEqual(b'', exc.challenge)
        else:
            self.fail('ServerChallenge not raised')

    def test_server_attempt_bad_response(self):
        resp = ServerChallenge(b'')
        resp.set_response(b'abcdefghi')
        self.assertRaises(AuthenticationError,
                          PlainMechanism.server_attempt, [resp])

    def test_server_attempt_successful(self):
        resp = ServerChallenge(b'')
        resp.set_response(b'abc\x00def\x00ghi')
        result = PlainMechanism.server_attempt([resp])
        self.assertEqual('abc', result.authzid)
        self.assertEqual('def', result.authcid)
        self.assertTrue(result.check_secret('ghi'))

    def test_client_attempt(self):
        creds = AuthenticationCredentials('testuser', 'testpass', 'testzid')
        resp1 = PlainMechanism.client_attempt(creds, [])
        self.assertEqual(b'testzid\x00testuser\x00testpass',
                         resp1.get_response())
        resp1.set_challenge(b'')
        resp2 = PlainMechanism.client_attempt(creds, [resp1])
        self.assertEqual(b'testzid\x00testuser\x00testpass',
                         resp2.get_response())
        self.assertRaises(UnexpectedAuthChallenge,
                          PlainMechanism.client_attempt,
                          creds, [resp1, resp2])
