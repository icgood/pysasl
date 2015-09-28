
from __future__ import absolute_import

import unittest

from pysasl import (SASLAuth, UnexpectedAuthChallenge,
                    AuthenticationCredentials)
from pysasl.oauth import OAuth2Mechanism


class TestOAuth2Mechanism(unittest.TestCase):

    def test_availability(self):
        sasl = SASLAuth([b'XOAUTH2'])
        self.assertEqual([OAuth2Mechanism], sasl.client_mechanisms)
        self.assertEqual([], sasl.server_mechanisms)
        self.assertEqual(OAuth2Mechanism, sasl.get(b'XOAUTH2'))

    def test_client_attempt(self):
        creds = AuthenticationCredentials('testuser', 'testtoken')
        resp1 = OAuth2Mechanism.client_attempt(creds, [])
        self.assertEqual(b'user=testuser\x01auth=Bearertesttoken\x01\x01',
                         resp1.get_response())
        resp1.set_challenge(b'')
        resp2 = OAuth2Mechanism.client_attempt(creds, [resp1])
        self.assertEqual(b'', resp2.get_response())
        self.assertRaises(UnexpectedAuthChallenge,
                          OAuth2Mechanism.client_attempt,
                          creds, [resp1, resp2])
