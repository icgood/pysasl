
from __future__ import absolute_import

import unittest

from pysasl.prep import noprep, saslprep


class TestPrep(unittest.TestCase):

    def test_noprep(self) -> None:
        self.assertEqual('I\u00ADX', noprep('I\u00ADX'))
        self.assertEqual('user', noprep('user'))
        self.assertEqual('USER', noprep('USER'))
        self.assertEqual('\u00AA', noprep('\u00AA'))
        self.assertEqual('\u2168', noprep('\u2168'))
        self.assertEqual('\u0007', noprep('\u0007'))
        self.assertEqual('\u0221', noprep('\u0221'))
        self.assertEqual('\u0627\u0031', noprep('\u0627\u0031'))
        self.assertEqual('\u0627\u00AA', noprep('\u0627\u00AA'))

    def test_saslprep(self) -> None:
        self.assertEqual('IX', saslprep('I\u00ADX'))
        self.assertEqual('user', saslprep('user'))
        self.assertEqual('USER', saslprep('USER'))
        self.assertEqual('a', saslprep('\u00AA'))
        self.assertEqual('IX', saslprep('\u2168'))
        self.assertRaises(ValueError, saslprep, '\u0007')
        self.assertRaises(ValueError, saslprep, '\u0221')
        self.assertRaises(ValueError, saslprep, '\u0627\u0031')
        self.assertRaises(ValueError, saslprep, '\u0627\u00AA')

    def test_saslprep_query(self) -> None:
        self.assertEqual('\u0221', saslprep('\u0221', allow_unassigned=True))
