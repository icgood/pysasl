
from __future__ import absolute_import

import unittest

from pysasl import (SASLAuth, ServerChallenge, ChallengeResponse,
                    UnexpectedChallenge)
from pysasl.creds import StoredSecret, AuthenticationCredentials
from pysasl.mechanisms.login import LoginMechanism


class TestLoginMechanism(unittest.TestCase):

    def setUp(self) -> None:
        self.mech = LoginMechanism()

    def test_availability(self) -> None:
        sasl = SASLAuth.defaults()
        self.assertIsInstance(sasl.get(b'LOGIN'), LoginMechanism)
        sasl = SASLAuth.named([b'LOGIN'])
        self.assertIsInstance(sasl.get(b'LOGIN'), LoginMechanism)
        sasl = SASLAuth([self.mech])
        self.assertEqual([self.mech], sasl.client_mechanisms)
        self.assertEqual([self.mech], sasl.server_mechanisms)
        self.assertEqual(self.mech, sasl.get(b'LOGIN'))

    def test_server_attempt_issues_challenges(self) -> None:
        try:
            self.mech.server_attempt([])
        except ServerChallenge as exc:
            self.assertEqual(b'Username:', exc.data)
        else:
            self.fail('first ServerChallenge not raised')
        try:
            self.mech.server_attempt([
                ChallengeResponse(b'', b'test')])
        except ServerChallenge as exc:
            self.assertEqual(b'Password:', exc.data)
        else:
            self.fail('second ServerChallenge not raised')

    def test_server_attempt_successful(self) -> None:
        result, final = self.mech.server_attempt([
            ChallengeResponse(b'Username:', b'testuser'),
            ChallengeResponse(b'Password:', b'testpass')])
        self.assertIsNone(final)
        self.assertIsNone(result.authcid_type)
        self.assertTrue(result.has_secret)
        self.assertIsNone(result.authzid)
        self.assertEqual('testuser', result.authcid)
        self.assertEqual('testuser', result.identity)
        self.assertTrue(result.check_secret(StoredSecret('testpass')))
        self.assertFalse(result.check_secret(StoredSecret('invalid')))

    def test_client_attempt(self) -> None:
        creds = AuthenticationCredentials('testuser', 'testpass')
        resp1 = self.mech.client_attempt(creds, [])
        self.assertEqual(b'', resp1.response)
        resp2 = self.mech.client_attempt(creds, [
            ServerChallenge(b'Username:')])
        self.assertEqual(b'testuser', resp2.response)
        resp3 = self.mech.client_attempt(creds, [
            ServerChallenge(b'Username:'), ServerChallenge(b'Password:')])
        self.assertEqual(b'testpass', resp3.response)
        self.assertRaises(UnexpectedChallenge,
                          self.mech.client_attempt,
                          creds, [
                              ServerChallenge(b'Username:'),
                              ServerChallenge(b'Password:'),
                              ServerChallenge(b'')])
