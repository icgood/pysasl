
from __future__ import absolute_import

import unittest

from pysasl import (SASLAuth, ServerChallenge, ChallengeResponse,
                    UnexpectedChallenge, ExternalVerificationRequired)
from pysasl.creds import StoredSecret, AuthenticationCredentials
from pysasl.mechanisms.external import ExternalMechanism


class TestExternalMechanism(unittest.TestCase):

    def setUp(self) -> None:
        self.mech = ExternalMechanism()

    def test_availability(self) -> None:
        sasl = SASLAuth.defaults()
        self.assertIsNone(sasl.get(b'EXTERNAL'))
        sasl = SASLAuth.named([b'EXTERNAL'])
        self.assertIsInstance(sasl.get(b'EXTERNAL'), ExternalMechanism)
        sasl = SASLAuth([self.mech])
        self.assertEqual([self.mech], sasl.client_mechanisms)
        self.assertEqual([self.mech], sasl.server_mechanisms)
        self.assertEqual(self.mech, sasl.get(b'EXTERNAL'))

    def test_server_attempt_issues_challenge(self) -> None:
        try:
            self.mech.server_attempt([])
        except ServerChallenge as exc:
            self.assertEqual(b'', exc.data)
        else:
            self.fail('ServerChallenge not raised')

    def test_server_attempt_successful(self) -> None:
        result, final = self.mech.server_attempt([
            ChallengeResponse(b'', b'abcdefghi')])
        self.assertIsNone(final)
        self.assertIsNone(result.authcid_type)
        self.assertFalse(result.has_secret)
        self.assertEqual('abcdefghi', result.authzid)
        self.assertEqual('abcdefghi', result.authcid)
        self.assertEqual('abcdefghi', result.identity)
        self.assertRaises(AttributeError, getattr, result, 'secret')
        with self.assertRaises(ExternalVerificationRequired) as exc:
            result.check_secret(StoredSecret('secret'))
        self.assertIsNone(exc.exception.token)
        with self.assertRaises(ExternalVerificationRequired) as exc:
            result.check_secret(None)
        self.assertIsNone(exc.exception.token)

    def test_server_attempt_successful_empty(self) -> None:
        result, _ = self.mech.server_attempt([
            ChallengeResponse(b'', b'')])
        self.assertIsNone(result.authzid)
        self.assertEqual('', result.authcid)

    def test_client_attempt(self) -> None:
        creds = AuthenticationCredentials('', '', 'testzid')
        resp1 = self.mech.client_attempt(creds, [])
        self.assertEqual(b'testzid', resp1.response)
        resp2 = self.mech.client_attempt(creds, [ServerChallenge(b'')])
        self.assertEqual(b'testzid', resp2.response)
        self.assertRaises(UnexpectedChallenge,
                          self.mech.client_attempt,
                          creds, [ServerChallenge(b'')]*2)
