
from __future__ import absolute_import

import unittest
import uuid
import time

try:
    from unittest.mock import MagicMock, patch
except ImportError:
    from mock import MagicMock, patch

from pysasl import (ServerMechanism, IssueChallenge, ChallengeResponse,
    AuthenticationError)
from pysasl.crammd5 import CramMD5Mechanism


class TestCramMD5Mechanism(unittest.TestCase):

    def setUp(self):
        CramMD5Mechanism.hostname = 'testhost'
        self.crammd5 = CramMD5Mechanism()

    def test_available(self):
        avail = ServerMechanism.get_available()
        self.assertEqual(CramMD5Mechanism, avail.get('CRAM-MD5'))

    @patch.object(uuid, 'uuid4')
    @patch.object(time, 'time')
    def test_issues_challenge(self, time_mock, uuid4_mock):
        time_mock.return_value = 1234.0
        uuid4_mock.return_value = MagicMock(hex='abc123')
        try:
            self.crammd5.server_attempt([])
        except IssueChallenge as exc:
            self.assertEqual('<abc123.1234@testhost>', exc.challenge.challenge)
        else:
            self.fail('IssueChallenge not raised')

    @patch.object(uuid, 'uuid4')
    @patch.object(time, 'time')
    def test_bad_response(self, time_mock, uuid4_mock):
        time_mock.return_value = 1234.0
        uuid4_mock.return_value = MagicMock(hex='abc123')
        resp = ChallengeResponse(response='testing')
        self.assertRaises(AuthenticationError,
                          self.crammd5.server_attempt, [resp])

    @patch.object(uuid, 'uuid4')
    @patch.object(time, 'time')
    def test_successful(self, time_mock, uuid4_mock):
        time_mock.return_value = 1234.0
        uuid4_mock.return_value = MagicMock(hex='abc123')
        response = 'testuser 3a569c3950e95c490fd42f5d89e1ef67'
        resp = ChallengeResponse(challenge='<abc123.1234@testhost>',
                                 response=response)
        result = self.crammd5.server_attempt([resp])
        self.assertTrue(result.authzid is None)
        self.assertEqual('testuser', result.authcid)
        self.assertTrue(result.check_secret('testpass'))
        self.assertFalse(result.check_secret('badpass'))
