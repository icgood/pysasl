
from __future__ import absolute_import

import unittest

from pysasl.creds import StoredSecret, AuthenticationCredentials
from pysasl.hashing import BuiltinHash

builtin_hash = BuiltinHash(rounds=1000)

password_sha256 = '6f3b2db13d217e79d70d43d326a6e485756bcbe1b4e959f3e86c0d9eb' \
    '62fa40a352c178b1fc30896e7c484d74a78561d'
password_sha512 = '1339152519f33e66bf15837624ce57563f680e5d2a2700a5016cb087c' \
    '5c05b3e22ba040a32f9453dbcb13071966bdb88cf5e8b0be68c3026094ff67bf03475c2' \
    '2a15e9e39d5fcbe07a0c62296f155999'


class TestHashing(unittest.TestCase):

    def test_builtin_good(self) -> None:
        creds = AuthenticationCredentials('username', 'password')
        stored = StoredSecret(password_sha256, hash=builtin_hash)
        self.assertTrue(creds.check_secret(stored))

    def test_builtin_invalid(self) -> None:
        creds = AuthenticationCredentials('username', 'invalid')
        stored = StoredSecret(password_sha256, hash=builtin_hash)
        self.assertFalse(creds.check_secret(stored))

    def test_builtin_copy(self) -> None:
        creds = AuthenticationCredentials('username', 'password')
        builtin_copy = builtin_hash.copy()
        stored = StoredSecret(password_sha256, hash=builtin_copy)
        self.assertTrue(creds.check_secret(stored))
        builtin_copy = builtin_hash.copy(hash_name='sha512')
        stored = StoredSecret(password_sha512, hash=builtin_copy)
        self.assertTrue(creds.check_secret(stored))

    def test_cleartext_good(self) -> None:
        creds = AuthenticationCredentials('username', 'password')
        self.assertTrue(creds.check_secret(StoredSecret('password')))

    def test_cleartext_invalid(self) -> None:
        creds = AuthenticationCredentials('username', 'invalid')
        self.assertFalse(creds.check_secret(StoredSecret('password')))

    def test_cleartext_copy(self) -> None:
        creds = AuthenticationCredentials('username', 'password')
        stored = StoredSecret('password')
        self.assertTrue(creds.check_secret(stored))
        stored = StoredSecret('password', hash=stored.hash.copy())
        self.assertTrue(creds.check_secret(stored))

    def test_none(self) -> None:
        creds = AuthenticationCredentials('username', 'password')
        self.assertFalse(creds.check_secret(None))
