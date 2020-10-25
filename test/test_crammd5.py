
from __future__ import absolute_import

import unittest
import email.utils

from unittest.mock import patch

from pysasl import (SASLAuth, ServerChallenge, ChallengeResponse,
                    AuthenticationError, UnexpectedChallenge)
from pysasl.creds import StoredSecret, AuthenticationCredentials
from pysasl.mechanisms.crammd5 import CramMD5Mechanism


class TestCramMD5Mechanism(unittest.TestCase):

    def setUp(self) -> None:
        self.mech = CramMD5Mechanism()

    def test_availability(self) -> None:
        sasl = SASLAuth.defaults()
        self.assertIsNone(sasl.get(b'CRAM-MD5'))
        sasl = SASLAuth.named([b'CRAM-MD5'])
        self.assertIsInstance(sasl.get(b'CRAM-MD5'), CramMD5Mechanism)
        sasl = SASLAuth([self.mech])
        self.assertEqual([self.mech], sasl.client_mechanisms)
        self.assertEqual([self.mech], sasl.server_mechanisms)
        self.assertEqual(self.mech, sasl.get(b'CRAM-MD5'))

    @patch.object(email.utils, 'make_msgid')
    def test_server_attempt_issues_challenge(self, make_msgid_mock) -> None:
        make_msgid_mock.return_value = '<abc123.1234@testhost>'
        try:
            self.mech.server_attempt([])
        except ServerChallenge as exc:
            self.assertEqual(b'<abc123.1234@testhost>', exc.data)
        else:
            self.fail('ServerChallenge not raised')

    @patch.object(email.utils, 'make_msgid')
    def test_server_attempt_bad_response(self, make_msgid_mock) -> None:
        make_msgid_mock.return_value = '<abc123.1234@testhost>'
        self.assertRaises(AuthenticationError,
                          self.mech.server_attempt,
                          [ChallengeResponse(b'', b'testing')])

    @patch.object(email.utils, 'make_msgid')
    def test_server_attempt_successful(self, make_msgid_mock) -> None:
        make_msgid_mock.return_value = '<abc123.1234@testhost>'
        response = b'testuser 3a569c3950e95c490fd42f5d89e1ef67'
        result, final = self.mech.server_attempt([
            ChallengeResponse(b'<abc123.1234@testhost>', response)])
        self.assertIsNone(final)
        self.assertIsNone(result.authcid_type)
        self.assertFalse(result.has_secret)
        self.assertIsNone(result.authzid)
        self.assertEqual('testuser', result.authcid)
        self.assertEqual('testuser', result.identity)
        self.assertRaises(AttributeError, getattr, result, 'secret')
        self.assertTrue(result.check_secret(StoredSecret('testpass')))
        self.assertTrue(result.check_secret(StoredSecret('testpass')))
        self.assertFalse(result.check_secret(StoredSecret('badpass')))
        self.assertFalse(result.check_secret(None))

    def test_client_attempt(self) -> None:
        creds = AuthenticationCredentials('testuser', 'testpass')
        resp1 = self.mech.client_attempt(creds, [])
        self.assertEqual(b'', resp1.response)
        resp2 = self.mech.client_attempt(creds, [
            ServerChallenge(b'<abc123.1234@testhost>')])
        self.assertEqual(b'testuser 3a569c3950e95c490fd42f5d89e1ef67',
                         resp2.response)
        self.assertRaises(UnexpectedChallenge,
                          self.mech.client_attempt,
                          creds, [ServerChallenge(b'')]*2)
