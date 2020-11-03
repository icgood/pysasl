
from __future__ import absolute_import

import unittest

from pysasl import SASLAuth, UnexpectedChallenge, ServerChallenge, \
    ChallengeResponse, AuthenticationError, ExternalVerificationRequired
from pysasl.creds import StoredSecret, AuthenticationCredentials
from pysasl.mechanisms.oauth import OAuth2Mechanism


class TestOAuth2Mechanism(unittest.TestCase):

    def setUp(self) -> None:
        self.mech = OAuth2Mechanism()

    def test_availability(self) -> None:
        sasl = SASLAuth.defaults()
        self.assertIsNone(sasl.get(b'XOAUTH2'))
        sasl = SASLAuth.named([b'XOAUTH2'])
        self.assertIsInstance(sasl.get(b'XOAUTH2'), OAuth2Mechanism)
        sasl = SASLAuth([self.mech])
        self.assertEqual([self.mech], sasl.client_mechanisms)
        self.assertEqual([self.mech], sasl.server_mechanisms)
        self.assertEqual(self.mech, sasl.get(b'XOAUTH2'))

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
        result, final = self.mech.server_attempt([ChallengeResponse(
            b'', b'user=testuser\x01auth=Bearer testtoken\x01\x01')])
        self.assertIsNone(final)
        self.assertIsNone(result.authcid_type)
        self.assertFalse(result.has_secret)
        self.assertEqual('testuser', result.authcid)
        self.assertIsNone(result.authzid)
        self.assertEqual('testuser', result.identity)
        self.assertRaises(AttributeError, getattr, result, 'secret')
        with self.assertRaises(ExternalVerificationRequired) as exc:
            result.check_secret(StoredSecret('secret'))
        self.assertEqual('testtoken', exc.exception.token)
        with self.assertRaises(ExternalVerificationRequired) as exc:
            result.check_secret(None)
        self.assertEqual('testtoken', exc.exception.token)

    def test_client_attempt(self) -> None:
        creds = AuthenticationCredentials('testuser', 'testtoken')
        resp1 = self.mech.client_attempt(creds, [])
        self.assertEqual(b'user=testuser\x01auth=Bearer testtoken\x01\x01',
                         resp1.response)
        resp2 = self.mech.client_attempt(creds, [ServerChallenge(b'')])
        self.assertEqual(b'user=testuser\x01auth=Bearer testtoken\x01\x01',
                         resp2.response)
        self.assertRaises(UnexpectedChallenge,
                          self.mech.client_attempt,
                          creds, [ServerChallenge(b'')]*2)
