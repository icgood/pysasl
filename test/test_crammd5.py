
from __future__ import absolute_import

import unittest
import email.utils

from unittest.mock import patch, Mock

from pysasl import SASLAuth
from pysasl.config import default_config
from pysasl.creds.client import ClientCredentials
from pysasl.exception import (InvalidResponse, MechanismUnusable,
                              UnexpectedChallenge)
from pysasl.hashing import BuiltinHash
from pysasl.identity import ClearIdentity, HashedIdentity
from pysasl.mechanism import ServerChallenge, ChallengeResponse
from pysasl.mechanism.crammd5 import CramMD5Result, CramMD5Mechanism

builtin_hash = BuiltinHash(rounds=1000)


class TestCramMD5Mechanism(unittest.TestCase):

    def setUp(self) -> None:
        self.mech = CramMD5Mechanism()

    def test_availability(self) -> None:
        sasl = SASLAuth.defaults()
        self.assertIsNone(sasl.get_server(b'CRAM-MD5'))
        self.assertIsNone(sasl.get_client(b'CRAM-MD5'))
        sasl = SASLAuth.named([b'CRAM-MD5'])
        self.assertEqual(self.mech, sasl.get_server(b'CRAM-MD5'))
        self.assertEqual(self.mech, sasl.get_client(b'CRAM-MD5'))
        sasl = SASLAuth([self.mech])
        self.assertEqual([self.mech], sasl.client_mechanisms)
        self.assertEqual([self.mech], sasl.server_mechanisms)

    def test_result_verify_impossible(self) -> None:
        result = CramMD5Result('testuser', b'', b'', config=default_config)
        identity = HashedIdentity('testuser', 'digest',
                                  hash=builtin_hash.copy())
        with self.assertRaises(MechanismUnusable):
            result.verify(identity)

    @patch.object(email.utils, 'make_msgid')
    def test_server_attempt_issues_challenge(
            self, make_msgid_mock: Mock) -> None:
        make_msgid_mock.return_value = '<abc123.1234@testhost>'
        with self.assertRaises(ServerChallenge) as raised:
            self.mech.server_attempt([])
        self.assertEqual(b'<abc123.1234@testhost>', raised.exception.data)

    @patch.object(email.utils, 'make_msgid')
    def test_server_attempt_bad_response(self, make_msgid_mock: Mock) -> None:
        make_msgid_mock.return_value = '<abc123.1234@testhost>'
        self.assertRaises(InvalidResponse,
                          self.mech.server_attempt,
                          [ChallengeResponse(b'', b'testing')])

    @patch.object(email.utils, 'make_msgid')
    def test_server_attempt_successful(self, make_msgid_mock: Mock) -> None:
        make_msgid_mock.return_value = '<abc123.1234@testhost>'
        response = b'testuser 3a569c3950e95c490fd42f5d89e1ef67'
        result, final = self.mech.server_attempt([
            ChallengeResponse(b'<abc123.1234@testhost>', response)])
        self.assertIsNone(final)
        self.assertIsInstance(result, CramMD5Result)
        self.assertEqual('testuser', result.authcid)
        self.assertEqual('testuser', result.authzid)
        self.assertTrue(result.verify(ClearIdentity('testuser', 'testpass')))
        self.assertTrue(result.verify(ClearIdentity('testuser', 'testpass')))
        self.assertFalse(result.verify(ClearIdentity('testuser', 'badpass')))
        self.assertFalse(result.verify(ClearIdentity('baduser', 'testpass')))
        self.assertFalse(result.verify(None))

    def test_client_attempt(self) -> None:
        creds = ClientCredentials('testuser', 'testpass')
        resp1 = self.mech.client_attempt(creds, [])
        self.assertEqual(b'', resp1.response)
        resp2 = self.mech.client_attempt(creds, [
            ServerChallenge(b'<abc123.1234@testhost>')])
        self.assertEqual(b'testuser 3a569c3950e95c490fd42f5d89e1ef67',
                         resp2.response)
        self.assertRaises(UnexpectedChallenge,
                          self.mech.client_attempt,
                          creds, [ServerChallenge(b'')]*2)
