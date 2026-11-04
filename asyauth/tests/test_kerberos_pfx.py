import unittest

from asyauth.common.credentials import UniCredential
from asyauth.common.credentials import kerberos as kerberos_mod
from asyauth.common.constants import asyauthSecret, asyauthProtocol


class TestKerberosPFXNoPassword(unittest.TestCase):
    """A PFX file frequently has no password. Authenticating with such a file
    through the URL format must not require a password to be set.

    The actual PFX parsing lives in minikerberos (KCRED.from_pfx ->
    from_pfx_string, which already defaults a missing password to b''); here we
    verify the asyauth URL layer parses a password-less PFX URL and dispatches
    to minikerberos with a None password, without requiring oscrypto.
    """

    def test_from_url_pfx_without_password(self):
        url = 'ldap+kerberos-pfx://TEST\\victim@10.10.10.2/?dc=10.10.10.2&keydata=cert.pfx'
        cred = UniCredential.from_url(url)
        self.assertEqual(cred.protocol, asyauthProtocol.KERBEROS)
        self.assertEqual(cred.stype, asyauthSecret.PFX)
        self.assertIsNone(cred.secret)
        self.assertEqual(cred.keydata, 'cert.pfx')

    def test_from_url_pfx_with_empty_password(self):
        url = 'ldap+kerberos-pfx://TEST\\victim:@10.10.10.2/?dc=10.10.10.2&keydata=cert.pfx'
        cred = UniCredential.from_url(url)
        self.assertEqual(cred.stype, asyauthSecret.PFX)
        self.assertEqual(cred.secret, '')

    def test_to_ccred_passes_none_password(self):
        url = 'ldap+kerberos-pfx://TEST\\victim@10.10.10.2/?dc=10.10.10.2&keydata=cert.pfx'
        cred = UniCredential.from_url(url)

        captured = {}

        def fake_from_pfx(data, password, *args, **kwargs):
            captured['data'] = data
            captured['password'] = password
            return 'CCRED_SENTINEL'

        original = kerberos_mod.KCRED.from_pfx
        kerberos_mod.KCRED.from_pfx = staticmethod(fake_from_pfx)
        try:
            result = cred.to_ccred()
        finally:
            kerberos_mod.KCRED.from_pfx = original

        # to_ccred must dispatch to from_pfx with the pfx file and a None
        # password (i.e. it must NOT require a password to be set).
        self.assertEqual(result, 'CCRED_SENTINEL')
        self.assertEqual(captured['data'], 'cert.pfx')
        self.assertIsNone(captured['password'])


if __name__ == '__main__':
    unittest.main()
