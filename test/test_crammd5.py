
from __future__ import absolute_import

import unittest
import email.utils

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch  # type: ignore

from pysasl import (SASLAuth, ServerChallenge, AuthenticationError,
                    UnexpectedAuthChallenge, AuthenticationCredentials)
from pysasl.crammd5 import CramMD5Mechanism


class TestCramMD5Mechanism(unittest.TestCase):

    def setUp(self):
        self.mech = CramMD5Mechanism()

    def test_availability(self):
        sasl = SASLAuth()
        self.assertIsInstance(sasl.get(b'CRAM-MD5'), CramMD5Mechanism)
        sasl = SASLAuth([b'CRAM-MD5'])
        self.assertIsInstance(sasl.get(b'CRAM-MD5'), CramMD5Mechanism)
        sasl = SASLAuth([self.mech])
        self.assertEqual([self.mech], sasl.client_mechanisms)
        self.assertEqual([self.mech], sasl.server_mechanisms)
        self.assertEqual(self.mech, sasl.get(b'CRAM-MD5'))

    @patch.object(email.utils, 'make_msgid')
    def test_server_attempt_issues_challenge(self, make_msgid_mock):
        make_msgid_mock.return_value = '<abc123.1234@testhost>'
        try:
            self.mech.server_attempt([])
        except ServerChallenge as exc:
            self.assertEqual(b'<abc123.1234@testhost>', exc.challenge)
        else:
            self.fail('ServerChallenge not raised')

    @patch.object(email.utils, 'make_msgid')
    def test_server_attempt_bad_response(self, make_msgid_mock):
        make_msgid_mock.return_value = '<abc123.1234@testhost>'
        resp = ServerChallenge(b'')
        resp.set_response(b'testing')
        self.assertRaises(AuthenticationError,
                          self.mech.server_attempt, [resp])

    @patch.object(email.utils, 'make_msgid')
    def test_server_attempt_successful(self, make_msgid_mock):
        make_msgid_mock.return_value = '<abc123.1234@testhost>'
        response = b'testuser 3a569c3950e95c490fd42f5d89e1ef67'
        resp = ServerChallenge(b'<abc123.1234@testhost>')
        resp.set_response(response)
        result, final = self.mech.server_attempt([resp])
        self.assertIsNone(final)
        self.assertFalse(result.has_secret)
        self.assertIsNone(result.authzid)
        self.assertEqual('testuser', result.authcid)
        self.assertEqual('testuser', result.identity)
        self.assertRaises(AttributeError, getattr, result, 'secret')
        self.assertTrue(result.check_secret(u'testpass'))
        self.assertTrue(result.check_secret(b'testpass'))
        self.assertFalse(result.check_secret('badpass'))

    def test_client_attempt(self):
        creds = AuthenticationCredentials('testuser', 'testpass')
        resp1 = self.mech.client_attempt(creds, [])
        self.assertEqual(b'', resp1.get_response())
        resp1.set_challenge(b'<abc123.1234@testhost>')
        resp2 = self.mech.client_attempt(creds, [resp1])
        self.assertEqual(b'testuser 3a569c3950e95c490fd42f5d89e1ef67',
                         resp2.get_response())
        self.assertRaises(UnexpectedAuthChallenge,
                          self.mech.client_attempt,
                          creds, [resp1, resp2])
