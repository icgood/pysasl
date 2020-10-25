
from __future__ import absolute_import

import unittest

from pysasl import (SASLAuth, ServerChallenge, ChallengeResponse,
                    AuthenticationError, UnexpectedChallenge)
from pysasl.creds import StoredSecret, AuthenticationCredentials
from pysasl.mechanisms.plain import PlainMechanism


class TestPlainMechanism(unittest.TestCase):

    def setUp(self) -> None:
        self.mech = PlainMechanism()

    def test_availability(self) -> None:
        sasl = SASLAuth.defaults()
        self.assertIsInstance(sasl.get(b'PLAIN'), PlainMechanism)
        sasl = SASLAuth.named([b'PLAIN'])
        self.assertIsInstance(sasl.get(b'PLAIN'), PlainMechanism)
        sasl = SASLAuth([self.mech])
        self.assertEqual([self.mech], sasl.client_mechanisms)
        self.assertEqual([self.mech], sasl.server_mechanisms)
        self.assertEqual(self.mech, sasl.get(b'PLAIN'))

    def test_server_attempt_issues_challenge(self) -> None:
        try:
            self.mech.server_attempt([])
        except ServerChallenge as exc:
            self.assertEqual(b'', exc.data)
        else:
            self.fail('ServerChallenge not raised')

    def test_server_attempt_bad_response(self) -> None:
        self.assertRaises(AuthenticationError,
                          self.mech.server_attempt,
                          [ChallengeResponse(b'', b'abcdefghi')])

    def test_server_attempt_successful(self) -> None:
        result, final = self.mech.server_attempt([
            ChallengeResponse(b'', b'abc\x00def\x00ghi')])
        self.assertIsNone(final)
        self.assertIsNone(result.authcid_type)
        self.assertTrue(result.has_secret)
        self.assertEqual('abc', result.authzid)
        self.assertEqual('def', result.authcid)
        self.assertEqual('abc', result.identity)
        self.assertTrue(result.check_secret(StoredSecret('ghi')))
        self.assertFalse(result.check_secret(StoredSecret('invalid')))

    def test_client_attempt(self) -> None:
        creds = AuthenticationCredentials('testuser', 'testpass', 'testzid')
        resp1 = self.mech.client_attempt(creds, [])
        self.assertEqual(b'testzid\x00testuser\x00testpass', resp1.response)
        resp2 = self.mech.client_attempt(creds, [ServerChallenge(b'')])
        self.assertEqual(b'testzid\x00testuser\x00testpass', resp2.response)
        self.assertRaises(UnexpectedChallenge,
                          self.mech.client_attempt,
                          creds, [ServerChallenge(b'')]*2)
