
from __future__ import absolute_import

import unittest

from pysasl import (SASLAuth, UnexpectedChallenge, AuthenticationCredentials,
                    ServerChallenge)
from pysasl.oauth import OAuth2Mechanism


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
        self.assertEqual([], sasl.server_mechanisms)
        self.assertEqual(self.mech, sasl.get(b'XOAUTH2'))

    def test_client_attempt(self) -> None:
        creds = AuthenticationCredentials(u'testuser', u'testtoken')
        resp1 = self.mech.client_attempt(creds, [])
        self.assertEqual(b'user=testuser\x01auth=Bearertesttoken\x01\x01',
                         resp1.response)
        resp2 = self.mech.client_attempt(creds, [ServerChallenge(b'')])
        self.assertEqual(b'user=testuser\x01auth=Bearertesttoken\x01\x01',
                         resp2.response)
        self.assertRaises(UnexpectedChallenge,
                          self.mech.client_attempt,
                          creds, [ServerChallenge(b'')]*2)
