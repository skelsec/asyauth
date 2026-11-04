"""Comprehensive tests for asyauth credential URL / string parsing.

These are characterization tests: they assert the *current* behaviour of
``UniCredential.from_url`` / ``from_params`` / ``from_parts`` across every
protocol, secret type and sub-protocol, plus the relevant error paths and
query-parameter handling.

URL format reminder:
    scheme := <network>+[subproto-]<authproto>[-<secrettype>]
    e.g. ``smb2+ntlm-password://DOMAIN\\user:secret@host:port/?param=value``
"""

import platform
import unittest

from asyauth.common.credentials import UniCredential
from asyauth.common.credentials.ntlm import NTLMCredential
from asyauth.common.credentials.kerberos import KerberosCredential
from asyauth.common.credentials.spnego import SPNEGOCredential
from asyauth.common.credentials.credssp import CREDSSPCredential
from asyauth.common.constants import asyauthSecret, asyauthProtocol, asyauthSubProtocol
from asyauth.common.subprotocols import (
    SubProtocolNative,
    SubProtocolWSNet,
    SubProtocolWSNetDirect,
)

# 'Passw0rd!1' in the various encodings asyauth understands.
PW = 'Passw0rd!1'
PW_HEX = '50617373773072642131'
PW_B64 = 'UGFzc3cwcmQhMQ=='
NT_HASH = 'f8963568a1ec62a3161d9d6449baba93'
AES128 = '2511fa6466be6a454078e61e42e67b20'
DC = '10.10.10.2'


class TestFromUrlNTLM(unittest.TestCase):
    def test_password_aliases(self):
        for st in ('password', 'pass', 'pw'):
            cred = UniCredential.from_url('smb2+ntlm-%s://TEST\\user:%s@host' % (st, PW))
            self.assertIsInstance(cred, NTLMCredential)
            self.assertEqual(cred.protocol, asyauthProtocol.NTLM)
            self.assertEqual(cred.stype, asyauthSecret.PASSWORD)
            self.assertEqual(cred.secret, PW)
            self.assertEqual(cred.domain, 'TEST')
            self.assertEqual(cred.username, 'user')
            self.assertIsInstance(cred.subprotocol, SubProtocolNative)

    def test_password_hex(self):
        cred = UniCredential.from_url('smb2+ntlm-pwhex://TEST\\user:%s@host' % PW_HEX)
        self.assertEqual(cred.stype, asyauthSecret.PASSWORD)
        self.assertEqual(cred.secret, PW)

    def test_password_b64(self):
        cred = UniCredential.from_url('smb2+ntlm-pwb64://TEST\\user:%s@host' % PW_B64)
        self.assertEqual(cred.stype, asyauthSecret.PASSWORD)
        self.assertEqual(cred.secret, PW)

    def test_long_hex_password_stays_bytes(self):
        # >50 decoded bytes with an even length are treated as raw bytes
        # (e.g. machine account passwords), not decoded to a string.
        cred = UniCredential.from_url('smb2+ntlm-pwhex://TEST\\user:%s@host' % ('41' * 60))
        self.assertIsInstance(cred.secret, bytes)
        self.assertEqual(len(cred.secret), 60)

    def test_nt_hash(self):
        cred = UniCredential.from_url('smb2+ntlm-nt://TEST\\user:%s@host' % NT_HASH)
        self.assertEqual(cred.stype, asyauthSecret.NT)
        self.assertEqual(cred.secret, NT_HASH)

    def test_rc4_maps_to_nt(self):
        cred = UniCredential.from_url('smb2+ntlm-rc4://TEST\\user:%s@host' % NT_HASH)
        self.assertEqual(cred.stype, asyauthSecret.NT)
        self.assertEqual(cred.secret, NT_HASH)

    def test_anonymous_none_hostonly(self):
        cred = UniCredential.from_url('smb2+ntlm-none://host')
        self.assertEqual(cred.stype, asyauthSecret.NONE)
        self.assertIsNone(cred.secret)
        self.assertEqual(cred.username, '')
        self.assertEqual(cred.domain, '')
        self.assertTrue(cred.is_anonymous)

    def test_anonymous_scheme_without_secrettype(self):
        cred = UniCredential.from_url('smb2+ntlm://host')
        self.assertEqual(cred.protocol, asyauthProtocol.NTLM)
        self.assertEqual(cred.stype, asyauthSecret.NONE)
        self.assertTrue(cred.is_anonymous)

    def test_none_with_user_raises(self):
        with self.assertRaises(Exception):
            UniCredential.from_url('smb2+ntlm-none://TEST\\user@host')

    def test_unsupported_secret_type_raises(self):
        with self.assertRaises(Exception):
            UniCredential.from_url('smb2+ntlm-aes://TEST\\user:%s@host' % AES128)


class TestFromUrlSicily(unittest.TestCase):
    def test_sicily_password(self):
        cred = UniCredential.from_url('smb2+sicily-password://TEST\\user:%s@host' % PW)
        self.assertIsInstance(cred, NTLMCredential)
        self.assertEqual(cred.protocol, asyauthProtocol.SICILY)
        self.assertEqual(cred.stype, asyauthSecret.PASSWORD)

    def test_sicily_nt(self):
        cred = UniCredential.from_url('smb2+sicily-nt://TEST\\user:%s@host' % NT_HASH)
        self.assertEqual(cred.protocol, asyauthProtocol.SICILY)
        self.assertEqual(cred.stype, asyauthSecret.NT)


class TestFromUrlPlainSimpleNone(unittest.TestCase):
    def test_plain(self):
        cred = UniCredential.from_url('smb2+plain-password://TEST\\user:%s@host' % PW)
        self.assertIs(type(cred), UniCredential)
        self.assertEqual(cred.protocol, asyauthProtocol.PLAIN)
        self.assertEqual(cred.secret, PW)

    def test_none(self):
        cred = UniCredential.from_url('smb2+none-password://TEST\\user:%s@host' % PW)
        self.assertIs(type(cred), UniCredential)
        self.assertEqual(cred.protocol, asyauthProtocol.NONE)

    def test_simple(self):
        cred = UniCredential.from_url('smb2+simple-password://TEST\\user:%s@host' % PW)
        self.assertIs(type(cred), UniCredential)
        self.assertEqual(cred.protocol, asyauthProtocol.SIMPLE)


class TestFromUrlDomainParsing(unittest.TestCase):
    def test_dot_domain_becomes_none(self):
        cred = UniCredential.from_url('smb2+ntlm-password://.\\user:%s@host' % PW)
        self.assertIsNone(cred.domain)
        self.assertEqual(cred.username, 'user')

    def test_no_domain(self):
        cred = UniCredential.from_url('smb2+ntlm-password://user:%s@host' % PW)
        self.assertIsNone(cred.domain)
        self.assertEqual(cred.username, 'user')

    def test_special_chars_in_secret(self):
        cred = UniCredential.from_url('smb2+ntlm-password://TEST\\user:p@ss:w0rd@host')
        self.assertEqual(cred.secret, 'p@ss:w0rd')

    def test_url_encoded_secret(self):
        cred = UniCredential.from_url('smb2+ntlm-password://TEST\\user:p%40ss@host')
        self.assertEqual(cred.secret, 'p@ss')


class TestFromUrlKerberos(unittest.TestCase):
    def _url(self, stype, secret, extra=''):
        return 'smb2+kerberos-%s://TEST\\user:%s@host/?dc=%s%s' % (stype, secret, DC, extra)

    def test_password_sets_target_dc(self):
        cred = UniCredential.from_url(self._url('password', PW))
        self.assertIsInstance(cred, KerberosCredential)
        self.assertEqual(cred.protocol, asyauthProtocol.KERBEROS)
        self.assertEqual(cred.stype, asyauthSecret.PASSWORD)
        self.assertEqual(cred.secret, PW)
        self.assertEqual(cred.domain, 'TEST')
        self.assertEqual(cred.username, 'user')
        self.assertEqual(cred.target.ip, DC)
        self.assertEqual(cred.target.dc_ip, DC)

    def test_password_encodings(self):
        self.assertEqual(UniCredential.from_url(self._url('pwhex', PW_HEX)).secret, PW)
        self.assertEqual(UniCredential.from_url(self._url('pwb64', PW_B64)).secret, PW)

    def test_nt_and_rc4_map_to_rc4(self):
        self.assertEqual(UniCredential.from_url(self._url('nt', NT_HASH)).stype, asyauthSecret.RC4)
        self.assertEqual(UniCredential.from_url(self._url('rc4', NT_HASH)).stype, asyauthSecret.RC4)

    def test_aes(self):
        cred = UniCredential.from_url(self._url('aes', AES128))
        self.assertEqual(cred.stype, asyauthSecret.AES)
        self.assertEqual(cred.secret, AES128)

    def test_file_secret_types_store_filename(self):
        # These store the filename as the secret; the file is only read later in
        # to_ccred(), so parsing does not touch the filesystem.
        for stype, enum_val in (
            ('ccache', asyauthSecret.CCACHE),
            ('ccachehex', asyauthSecret.CCACHEHEX),
            ('ccacheb64', asyauthSecret.CCACHEB64),
            ('keytab', asyauthSecret.KEYTAB),
            ('keytabhex', asyauthSecret.KEYTABHEX),
            ('keytabb64', asyauthSecret.KEYTABB64),
            ('kirbi', asyauthSecret.KIRBI),
            ('kirbihex', asyauthSecret.KIRBIHEX),
            ('kirbib64', asyauthSecret.KIRBIB64),
        ):
            cred = UniCredential.from_url(self._url(stype, 'a.file'))
            self.assertEqual(cred.stype, enum_val)
            self.assertEqual(cred.secret, 'a.file')

    def test_certstore(self):
        cred = UniCredential.from_url(self._url('certstore', 'MY'))
        self.assertEqual(cred.stype, asyauthSecret.CERTSTORE)
        self.assertEqual(cred.secret, 'MY')

    def test_pfx_without_password(self):
        cred = UniCredential.from_url('smb2+kerberos-pfx://TEST\\user@host/?dc=%s&keydata=a.pfx' % DC)
        self.assertEqual(cred.stype, asyauthSecret.PFX)
        self.assertIsNone(cred.secret)
        self.assertEqual(cred.keydata, 'a.pfx')

    def test_pfx_with_password(self):
        cred = UniCredential.from_url('smb2+kerberos-pfx://TEST\\user:%s@host/?dc=%s&keydata=a.pfx' % (PW, DC))
        self.assertEqual(cred.stype, asyauthSecret.PFX)
        self.assertEqual(cred.secret, PW)

    def test_pfx_encoded_variants(self):
        for stype, enum_val in (('pfxb64', asyauthSecret.PFXB64), ('pfxhex', asyauthSecret.PFXHEX)):
            cred = UniCredential.from_url('smb2+kerberos-%s://TEST\\user@host/?dc=%s&keydata=DATA' % (stype, DC))
            self.assertEqual(cred.stype, enum_val)
            self.assertEqual(cred.keydata, 'DATA')

    def test_pem(self):
        cred = UniCredential.from_url('smb2+kerberos-pem://TEST\\user@host/?dc=%s&certdata=a.pem&keydata=a.key' % DC)
        self.assertEqual(cred.stype, asyauthSecret.PEM)
        self.assertEqual(cred.certdata, 'a.pem')
        self.assertEqual(cred.keydata, 'a.key')

    def test_missing_dc_raises(self):
        with self.assertRaises(Exception):
            UniCredential.from_url('smb2+kerberos-password://TEST\\user:%s@host' % PW)

    def test_etype_param(self):
        cred = UniCredential.from_url(self._url('password', PW, '&etype=23'))
        self.assertEqual(cred.etypes, [23])

    def test_altname_altdomain(self):
        cred = UniCredential.from_url(
            'smb2+kerberos-pfx://TEST\\user@host/?dc=%s&keydata=a.pfx&altname=foo&altdomain=bar.corp' % DC)
        self.assertEqual(cred.altname, 'foo')
        self.assertEqual(cred.altdomain, 'bar.corp')

    def test_cross_domain(self):
        cred = UniCredential.from_url(self._url('password', PW, '&dcc=5.6.7.8&realmc=OTHER.CORP'))
        self.assertEqual(cred.cross_realm, 'OTHER.CORP')
        self.assertIsNotNone(cred.cross_target)
        self.assertEqual(cred.cross_target.dc_ip, '5.6.7.8')

    def test_proxy_params(self):
        cred = UniCredential.from_url(
            self._url('password', PW, '&proxytype=socks5&proxyhost=127.0.0.1&proxyport=1080'))
        self.assertIsNotNone(cred.target.proxies)


class TestFromUrlSubProtocols(unittest.TestCase):
    def test_wsnet(self):
        cred = UniCredential.from_url('smb2+wsnet-ntlm://TEST\\user:%s@host' % PW)
        self.assertIsInstance(cred, NTLMCredential)
        self.assertIsInstance(cred.subprotocol, SubProtocolWSNet)
        self.assertEqual(cred.subprotocol.type, asyauthSubProtocol.WSNET)
        self.assertEqual(cred.secret, PW)

    def test_wsnetdirect(self):
        cred = UniCredential.from_url(
            'smb2+wsnetdirect-ntlm://TEST\\user:%s@host/?wsip=1.2.3.4&wsport=9000&wsproto=wss' % PW)
        self.assertIsInstance(cred.subprotocol, SubProtocolWSNetDirect)
        self.assertEqual(cred.subprotocol.ip, '1.2.3.4')
        self.assertEqual(str(cred.subprotocol.port), '9000')
        self.assertEqual(cred.subprotocol.proto, 'wss')

    def test_wsnetdirect_requires_wsip(self):
        with self.assertRaises(Exception):
            UniCredential.from_url('smb2+wsnetdirect-ntlm://TEST\\user:%s@host' % PW)

    def test_sspi(self):
        url = 'smb2+sspi-ntlm://TEST\\user@host'
        if platform.system() == 'Windows':
            cred = UniCredential.from_url(url)
            self.assertEqual(cred.subprotocol.type, asyauthSubProtocol.SSPI)
        else:
            # SubProtocolSSPI refuses to instantiate off Windows.
            with self.assertRaises(Exception):
                UniCredential.from_url(url)


class TestFromUrlCompositeScheme(unittest.TestCase):
    def test_spnego_ntlm_scheme(self):
        # A two-token auth tag matching a composite protocol enum resolves to
        # that composite protocol (and currently yields a plain UniCredential).
        cred = UniCredential.from_url('smb2+spnego-ntlm://TEST\\user:%s@host' % PW)
        self.assertEqual(cred.protocol, asyauthProtocol.SPNEGO_NTLM)
        self.assertEqual(cred.secret, PW)


class TestFromUrlErrors(unittest.TestCase):
    def test_bogus_protocol(self):
        with self.assertRaises(Exception):
            UniCredential.from_url('smb2+bogusproto-password://TEST\\user:%s@host' % PW)

    def test_bogus_secret_type(self):
        with self.assertRaises(Exception):
            UniCredential.from_url('smb2+ntlm-bogus://TEST\\user:%s@host' % PW)


class TestFromParams(unittest.TestCase):
    def test_ntlm(self):
        cred = UniCredential.from_params('ntlm-password', username='user', domain='TEST', secret=PW)
        self.assertIsInstance(cred, NTLMCredential)
        self.assertEqual(cred.protocol, asyauthProtocol.NTLM)

    def test_ntlm_nt_with_domain_in_username(self):
        cred = UniCredential.from_params('ntlm-nt', username='TEST\\user', secret=NT_HASH)
        self.assertEqual(cred.domain, 'TEST')
        self.assertEqual(cred.username, 'user')
        self.assertEqual(cred.stype, asyauthSecret.NT)

    def test_kerberos(self):
        cred = UniCredential.from_params('kerberos-password', username='user', domain='TEST', secret=PW, dc=DC)
        self.assertIsInstance(cred, KerberosCredential)
        self.assertEqual(cred.target.dc_ip, DC)

    def test_spnego_ntlm_wraps(self):
        cred = UniCredential.from_params('spnego-ntlm-password', username='user', domain='TEST', secret=PW)
        self.assertIsInstance(cred, SPNEGOCredential)

    def test_credssp_ntlm_wraps(self):
        cred = UniCredential.from_params('credssp-ntlm-password', username='user', domain='TEST', secret=PW)
        self.assertIsInstance(cred, CREDSSPCredential)

    def test_credssp_kerberos_wraps(self):
        cred = UniCredential.from_params('credssp-kerberos-password', username='user', domain='TEST', secret=PW, dc=DC)
        self.assertIsInstance(cred, CREDSSPCredential)

    def test_invalid_authproto_raises(self):
        with self.assertRaises(Exception):
            UniCredential.from_params('ntlm', username='user', secret=PW)

    def test_wsnet_subprotocol(self):
        # The first token is parsed as a sub-protocol (no secret type).
        cred = UniCredential.from_params('wsnet-ntlm', username='user', domain='TEST', secret=PW)
        self.assertIsInstance(cred, NTLMCredential)
        self.assertEqual(cred.subprotocol.type, asyauthSubProtocol.WSNET)

    def test_sspi_ntlm(self):
        # "sspi-ntlm" must resolve NTLM under the SSPI sub-protocol. SubProtocolSSPI
        # only instantiates on Windows, so off-Windows this reaches (and fails in)
        # SubProtocolSSPI rather than mis-parsing 'SSPI' as a protocol.
        if platform.system() == 'Windows':
            cred = UniCredential.from_params('sspi-ntlm', username='user', domain='TEST')
            self.assertIsInstance(cred, NTLMCredential)
            self.assertEqual(cred.subprotocol.type, asyauthSubProtocol.SSPI)
        else:
            with self.assertRaises(Exception) as ctx:
                UniCredential.from_params('sspi-ntlm', username='user', domain='TEST')
            self.assertIn('Windows', str(ctx.exception))


class TestFromParts(unittest.TestCase):
    def test_ntlm(self):
        cred = UniCredential.from_parts(
            asyauthProtocol.NTLM, asyauthSecret.PASSWORD, PW, 'user', 'TEST')
        self.assertIsInstance(cred, NTLMCredential)
        self.assertEqual(cred.protocol, asyauthProtocol.NTLM)
        self.assertEqual(cred.secret, PW)

    def test_kerberos_with_dc(self):
        cred = UniCredential.from_parts(
            asyauthProtocol.KERBEROS, asyauthSecret.PASSWORD, PW, 'user', 'TEST', dc=DC)
        self.assertIsInstance(cred, KerberosCredential)
        self.assertEqual(cred.target.dc_ip, DC)

    def test_domain_in_username_is_split(self):
        cred = UniCredential.from_parts(
            asyauthProtocol.NTLM, asyauthSecret.PASSWORD, PW, 'TEST\\user', None)
        self.assertEqual(cred.domain, 'TEST')
        self.assertEqual(cred.username, 'user')


if __name__ == '__main__':
    unittest.main()
