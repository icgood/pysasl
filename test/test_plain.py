
from __future__ import absolute_import

import unittest

from pysasl import SASLAuth
from pysasl.creds.client import ClientCredentials
from pysasl.creds.plain import PlainCredentials
from pysasl.exception import InvalidResponse, UnexpectedChallenge
from pysasl.identity import ClearIdentity
from pysasl.mechanism import ServerChallenge, ChallengeResponse
from pysasl.mechanism.plain import PlainMechanism


class TestPlainMechanism(unittest.TestCase):

    def setUp(self) -> None:
        self.mech = PlainMechanism()

    def test_availability(self) -> None:
        sasl = SASLAuth.defaults()
        self.assertEqual(self.mech, sasl.get_server(b'PLAIN'))
        self.assertEqual(self.mech, sasl.get_client(b'PLAIN'))
        sasl = SASLAuth.named([b'PLAIN'])
        self.assertEqual(self.mech, sasl.get_server(b'PLAIN'))
        self.assertEqual(self.mech, sasl.get_client(b'PLAIN'))
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
        result, final = self.mech.server_attempt([
            ChallengeResponse(b'', b'abc\x00def\x00ghi')])
        self.assertIsNone(final)
        self.assertIsInstance(result, PlainCredentials)
        self.assertEqual('abc', result.authzid)
        self.assertEqual('def', result.authcid)
        self.assertTrue(result.verify(ClearIdentity('def', 'ghi')))
        self.assertFalse(result.verify(ClearIdentity('def', 'invalid')))
        self.assertFalse(result.verify(ClearIdentity('invalid', 'ghi')))

    def test_client_attempt(self) -> None:
        creds = ClientCredentials('testuser', 'testpass', 'testzid')
        resp1 = self.mech.client_attempt(creds, [])
        self.assertEqual(b'testzid\x00testuser\x00testpass', resp1.response)
        resp2 = self.mech.client_attempt(creds, [ServerChallenge(b'')])
        self.assertEqual(b'testzid\x00testuser\x00testpass', resp2.response)
        self.assertRaises(UnexpectedChallenge,
                          self.mech.client_attempt,
                          creds, [ServerChallenge(b'')]*2)
