
from __future__ import absolute_import

import unittest

from pysasl.creds.plain import PlainCredentials
from pysasl.hashing import BuiltinHash, Cleartext
from pysasl.identity import ClearIdentity, HashedIdentity

builtin_hash = BuiltinHash(rounds=1000)

salt_sha256 = '6f3b2db13d217e79d70d43d326a6e485'
password_sha256 = salt_sha256 + '756bcbe1b4e959f3e86c0d9eb62fa40a352c178b1fc' \
    '30896e7c484d74a78561d'
password_sha512 = '1339152519f33e66bf15837624ce57563f680e5d2a2700a5016cb087c' \
    '5c05b3e22ba040a32f9453dbcb13071966bdb88cf5e8b0be68c3026094ff67bf03475c2' \
    '2a15e9e39d5fcbe07a0c62296f155999'


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
        salt = bytes.fromhex(salt_sha256)
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
