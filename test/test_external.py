
from __future__ import absolute_import

import unittest

from pysasl import (SASLAuth, ServerChallenge, UnexpectedAuthChallenge,
                    AuthenticationCredentials)
from pysasl.external import ExternalMechanism


class TestExternalMechanism(unittest.TestCase):

    def setUp(self):
        self.mech = ExternalMechanism()

    def test_availability(self):
        sasl = SASLAuth()
        self.assertIsNone(sasl.get(b'EXTERNAL'))
        sasl = SASLAuth([b'EXTERNAL'])
        self.assertIsInstance(sasl.get(b'EXTERNAL'), ExternalMechanism)
        sasl = SASLAuth([self.mech])
        self.assertEqual([self.mech], sasl.client_mechanisms)
        self.assertEqual([self.mech], sasl.server_mechanisms)
        self.assertEqual(self.mech, sasl.get(b'EXTERNAL'))

    def test_server_attempt_issues_challenge(self):
        try:
            self.mech.server_attempt([])
        except ServerChallenge as exc:
            self.assertEqual(b'', exc.challenge)
        else:
            self.fail('ServerChallenge not raised')

    def test_server_attempt_successful(self):
        resp = ServerChallenge(b'')
        resp.set_response(b'abcdefghi')
        result, final = self.mech.server_attempt([resp])
        self.assertIsNone(final)
        self.assertFalse(result.has_secret)
        self.assertEqual('abcdefghi', result.authzid)
        self.assertEqual('abcdefghi', result.authcid)
        self.assertEqual('abcdefghi', result.identity)
        self.assertRaises(AttributeError, getattr, result, 'secret')
        self.assertTrue(result.check_secret(u'secret'))
        self.assertTrue(result.check_secret(u'invalid'))

    def test_server_attempt_successful_empty(self):
        resp = ServerChallenge(b'')
        resp.set_response(b'')
        result, _ = self.mech.server_attempt([resp])
        self.assertIsNone(result.authzid)
        self.assertEqual('', result.authcid)

    def test_client_attempt(self):
        creds = AuthenticationCredentials(u'', u'', u'testzid')
        resp1 = self.mech.client_attempt(creds, [])
        self.assertEqual(b'testzid', resp1.get_response())
        resp2 = self.mech.client_attempt(creds, [resp1])
        self.assertEqual(b'testzid', resp1.get_response())
        self.assertRaises(UnexpectedAuthChallenge,
                          self.mech.client_attempt,
                          creds, [resp1, resp2])
