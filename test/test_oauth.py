
from __future__ import absolute_import

import unittest

from pysasl import SASLAuth
from pysasl.creds.client import ClientCredentials
from pysasl.creds.external import (ExternalVerificationRequired,
                                   ExternalCredentials)
from pysasl.exception import InvalidResponse, UnexpectedChallenge
from pysasl.identity import ClearIdentity
from pysasl.mechanism import ServerChallenge, ChallengeResponse
from pysasl.mechanism.oauth import OAuth2Mechanism


class TestOAuth2Mechanism(unittest.TestCase):

    def setUp(self) -> None:
        self.mech = OAuth2Mechanism()

    def test_availability(self) -> None:
        sasl = SASLAuth.defaults()
        self.assertIsNone(sasl.get_server(b'XOAUTH2'))
        self.assertIsNone(sasl.get_client(b'XOAUTH2'))
        sasl = SASLAuth.named([b'XOAUTH2'])
        self.assertEqual(self.mech, sasl.get_server(b'XOAUTH2'))
        self.assertEqual(self.mech, sasl.get_client(b'XOAUTH2'))
        sasl = SASLAuth([self.mech])
        self.assertEqual([self.mech], sasl.client_mechanisms)
        self.assertEqual([self.mech], sasl.server_mechanisms)

    def test_server_attempt_issues_challenge(self) -> None:
        try:
            self.mech.server_attempt([])
        except ServerChallenge as exc:
            self.assertEqual(b'', exc.data)
        else:
            self.fail('ServerChallenge not raised')

    def test_server_attempt_bad_response(self) -> None:
        self.assertRaises(InvalidResponse,
                          self.mech.server_attempt,
                          [ChallengeResponse(b'', b'abcdefghi')])

    def test_server_attempt_successful(self) -> None:
        result, final = self.mech.server_attempt([ChallengeResponse(
            b'', b'user=testuser\x01auth=Bearer testtoken\x01\x01')])
        self.assertIsNone(final)
        self.assertIsInstance(result, ExternalCredentials)
        self.assertEqual('', result.authcid)
        self.assertEqual('testuser', result.authzid)
        with self.assertRaises(ExternalVerificationRequired) as exc:
            result.verify(ClearIdentity('testuser', 'secret'))
        self.assertEqual('testtoken', exc.exception.token)
        with self.assertRaises(ExternalVerificationRequired) as exc:
            result.verify(None)
        self.assertEqual('testtoken', exc.exception.token)

    def test_client_attempt(self) -> None:
        creds = ClientCredentials('testuser', 'testtoken')
        resp1 = self.mech.client_attempt(creds, [])
        self.assertEqual(b'user=testuser\x01auth=Bearer testtoken\x01\x01',
                         resp1.response)
        resp2 = self.mech.client_attempt(creds, [ServerChallenge(b'')])
        self.assertEqual(b'user=testuser\x01auth=Bearer testtoken\x01\x01',
                         resp2.response)
        self.assertRaises(UnexpectedChallenge,
                          self.mech.client_attempt,
                          creds, [ServerChallenge(b'')]*2)

    def test_client_attempt_error(self) -> None:
        creds = ClientCredentials('testuser', 'testtoken')
        resp1 = self.mech.client_attempt(creds, [])
        self.assertEqual(b'user=testuser\x01auth=Bearer testtoken\x01\x01',
                         resp1.response)
        resp2 = self.mech.client_attempt(creds, [
            ServerChallenge(b'{"status":"401","schemes":"bearer mac",'
                            b'"scope":"https://mail.google.com/"}\n')])
        self.assertEqual(b'', resp2.response)
