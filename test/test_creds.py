
from __future__ import absolute_import

import base64
import unittest

from pysasl.creds.plain import PlainCredentials
from pysasl.hashing import BuiltinHash, Cleartext
from pysasl.identity import ClearIdentity, HashedIdentity

builtin_hash = BuiltinHash(rounds=1000)

salt_sha256 = 'bzstsT0hfnnXDUPTJqbkhQ=='
password_sha256 = 'bzstsT0hfnnXDUPTJqbkhXVry+G06Vnz6GwNnrYvpAo1LBeLH8MIlufEh' \
    'NdKeFYd'
password_sha512 = 'EzkVJRnzPma/FYN2JM5XVj9oDl0qJwClAWywh8XAWz4iugQKMvlFPbyxM' \
    'HGWa9uIz16LC+aMMCYJT/Z78DR1wioV6eOdX8vgegxiKW8VWZk='


class TestCreds(unittest.TestCase):

    def test_hashed_builtin_good(self) -> None:
        creds = PlainCredentials('username', 'password')
        stored = HashedIdentity('username', password_sha256, hash=builtin_hash)
        self.assertEqual(password_sha256, stored.digest)
        self.assertTrue(creds.verify(stored))
        self.assertIsNone(stored.get_clear_secret())

    def test_hashed_builtin_invalid(self) -> None:
        creds = PlainCredentials('username', 'invalid')
        stored = HashedIdentity('username', password_sha256, hash=builtin_hash)
        self.assertFalse(creds.verify(stored))

    def test_hashed_builtin_copy(self) -> None:
        creds = PlainCredentials('username', 'password')
        builtin_copy = builtin_hash.copy()
        stored = HashedIdentity.create('username', 'password',
                                       hash=builtin_copy)
        self.assertTrue(creds.verify(stored))
        builtin_copy = builtin_hash.copy()
        stored = HashedIdentity('username', password_sha256, hash=builtin_copy)
        self.assertTrue(creds.verify(stored))
        builtin_copy = builtin_hash.copy(hash_name='sha512')
        stored = HashedIdentity('username', password_sha512, hash=builtin_copy)
        self.assertTrue(creds.verify(stored))

    def test_builtin_hash(self) -> None:
        salt = base64.b64decode(salt_sha256)
        self.assertEqual(password_sha256,
                         builtin_hash.hash('password', salt))

    def test_cleartext_good(self) -> None:
        creds = PlainCredentials('username', 'password')
        stored = ClearIdentity('username', 'password')
        self.assertTrue(creds.verify(stored))

    def test_cleartext_invalid(self) -> None:
        creds = PlainCredentials('username', 'password')
        self.assertFalse(creds.verify(ClearIdentity('username', 'invalid')))
        self.assertFalse(creds.verify(ClearIdentity('invalid', 'password')))

    def test_cleartext_copy(self) -> None:
        creds = PlainCredentials('username', 'password')
        stored = HashedIdentity('username', 'password',
                                hash=Cleartext())
        self.assertTrue(creds.verify(stored))
        stored = HashedIdentity('username', 'password',
                                hash=stored.hash.copy())
        self.assertTrue(creds.verify(stored))

    def test_cleartext_hash(self) -> None:
        self.assertEqual('password', Cleartext().hash('password'))

    def test_none(self) -> None:
        creds = PlainCredentials('username', 'password')
        self.assertFalse(creds.verify(None))

    def test_get_clear_secret(self) -> None:
        clear1 = ClearIdentity('username', 'password')
        self.assertEqual('password', clear1.get_clear_secret())
        clear2 = HashedIdentity.create('username', 'password',
                                       hash=Cleartext())
        self.assertEqual('password', clear2.get_clear_secret())
        non_clear = HashedIdentity.create('username', 'password',
                                          hash=builtin_hash.copy())
        self.assertIsNone(non_clear.get_clear_secret())
