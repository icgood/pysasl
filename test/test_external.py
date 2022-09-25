
from __future__ import absolute_import

import unittest

from pysasl import SASLAuth
from pysasl.creds.client import ClientCredentials
from pysasl.creds.external import (ExternalVerificationRequired,
                                   ExternalCredentials)
from pysasl.exception import UnexpectedChallenge
from pysasl.identity import ClearIdentity
from pysasl.mechanism import ServerChallenge, ChallengeResponse
from pysasl.mechanism.external import ExternalMechanism


class TestExternalMechanism(unittest.TestCase):

    def setUp(self) -> None:
        self.mech = ExternalMechanism()

    def test_availability(self) -> None:
        sasl = SASLAuth.defaults()
        self.assertIsNone(sasl.get_server(b'EXTERNAL'))
        self.assertIsNone(sasl.get_client(b'EXTERNAL'))
        sasl = SASLAuth.named([b'EXTERNAL'])
        self.assertEqual(self.mech, sasl.get_server(b'EXTERNAL'))
        self.assertEqual(self.mech, sasl.get_client(b'EXTERNAL'))
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

    def test_server_attempt_successful(self) -> None:
        result, final = self.mech.server_attempt([
            ChallengeResponse(b'', b'testuser')])
        self.assertIsNone(final)
        self.assertIsInstance(result, ExternalCredentials)
        self.assertEqual('testuser', result.authzid)
        self.assertEqual('', result.authcid)
        with self.assertRaises(ExternalVerificationRequired) as exc:
            result.verify(ClearIdentity('testuser', 'testpass'))
        self.assertIsNone(exc.exception.token)
        with self.assertRaises(ExternalVerificationRequired) as exc:
            result.verify(None)
        self.assertIsNone(exc.exception.token)

    def test_server_attempt_successful_empty(self) -> None:
        result, _ = self.mech.server_attempt([
            ChallengeResponse(b'', b'')])
        self.assertEqual('', result.authzid)
        self.assertEqual('', result.authcid)

    def test_client_attempt(self) -> None:
        creds = ClientCredentials('', '', 'testzid')
        resp1 = self.mech.client_attempt(creds, [])
        self.assertEqual(b'testzid', resp1.response)
        resp2 = self.mech.client_attempt(creds, [ServerChallenge(b'')])
        self.assertEqual(b'testzid', resp2.response)
        self.assertRaises(UnexpectedChallenge,
                          self.mech.client_attempt,
                          creds, [ServerChallenge(b'')]*2)
