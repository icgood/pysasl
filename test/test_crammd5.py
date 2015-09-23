
from __future__ import absolute_import

import unittest
import email.utils

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

from pysasl import ServerChallenge, AuthenticationError
from pysasl.crammd5 import CramMD5Mechanism


class TestCramMD5Mechanism(unittest.TestCase):

    def setUp(self):
        CramMD5Mechanism.hostname = 'testhost'
        self.crammd5 = CramMD5Mechanism()

    @patch.object(email.utils, 'make_msgid')
    def test_issues_challenge(self, make_msgid_mock):
        make_msgid_mock.return_value = '<abc123.1234@testhost>'
        try:
            self.crammd5.server_attempt([])
        except ServerChallenge as exc:
            self.assertEqual(b'<abc123.1234@testhost>', exc.challenge)
        else:
            self.fail('ServerChallenge not raised')

    @patch.object(email.utils, 'make_msgid')
    def test_bad_response(self, make_msgid_mock):
        make_msgid_mock.return_value = '<abc123.1234@testhost>'
        resp = ServerChallenge(b'')
        resp.set_response(b'testing')
        self.assertRaises(AuthenticationError,
                          self.crammd5.server_attempt, [resp])

    @patch.object(email.utils, 'make_msgid')
    def test_successful(self, make_msgid_mock):
        make_msgid_mock.return_value = '<abc123.1234@testhost>'
        response = b'testuser 3a569c3950e95c490fd42f5d89e1ef67'
        resp = ServerChallenge(b'<abc123.1234@testhost>')
        resp.set_response(response)
        result = self.crammd5.server_attempt([resp])
        self.assertTrue(result.authzid is None)
        self.assertEqual('testuser', result.authcid)
        self.assertTrue(result.check_secret('testpass'))
        self.assertFalse(result.check_secret('badpass'))
