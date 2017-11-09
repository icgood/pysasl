
from __future__ import absolute_import

import unittest

from pysasl import (SASLAuth, ServerChallenge, AuthenticationCredentials,
                    UnexpectedAuthChallenge)
from pysasl.login import LoginMechanism


class TestLoginMechanism(unittest.TestCase):

    def setUp(self):
        self.mech = LoginMechanism()

    def test_availability(self):
        sasl = SASLAuth()
        self.assertIsInstance(sasl.get(b'LOGIN'), LoginMechanism)
        sasl = SASLAuth([b'LOGIN'])
        self.assertIsInstance(sasl.get(b'LOGIN'), LoginMechanism)
        sasl = SASLAuth([self.mech])
        self.assertEqual([self.mech], sasl.client_mechanisms)
        self.assertEqual([self.mech], sasl.server_mechanisms)
        self.assertEqual(self.mech, sasl.get(b'LOGIN'))

    def test_server_attempt_issues_challenges(self):
        try:
            self.mech.server_attempt([])
        except ServerChallenge as exc:
            self.assertEqual(b'Username:', exc.challenge)
        else:
            self.fail('first ServerChallenge not raised')
        try:
            self.mech.server_attempt(['test'])
        except ServerChallenge as exc:
            self.assertEqual(b'Password:', exc.challenge)
        else:
            self.fail('second ServerChallenge not raised')

    def test_server_attempt_successful(self):
        resp1 = ServerChallenge(b'Username:')
        resp1.set_response(b'testuser')
        resp2 = ServerChallenge(b'Password:')
        resp2.set_response(b'testpass')
        result = self.mech.server_attempt([resp1, resp2])
        self.assertTrue(result.authzid is None)
        self.assertEqual('testuser', result.authcid)
        self.assertTrue(result.check_secret('testpass'))

    def test_client_attempt(self):
        creds = AuthenticationCredentials('testuser', 'testpass')
        resp1 = self.mech.client_attempt(creds, [])
        self.assertEqual(b'', resp1.get_response())
        resp1.set_challenge(b'Username:')
        resp2 = self.mech.client_attempt(creds, [resp1])
        self.assertEqual(b'testuser', resp2.get_response())
        resp2.set_challenge(b'Password:')
        resp3 = self.mech.client_attempt(creds, [resp1, resp2])
        self.assertEqual(b'testpass', resp3.get_response())
        self.assertRaises(UnexpectedAuthChallenge,
                          self.mech.client_attempt,
                          creds, [resp1, resp2, resp3])
