import unittest

from asyauth.common.credentials import UniCredential
from asyauth.common.credentials.ntlm import NTLMCredential
from asyauth.common.credentials.spnego import SPNEGOCredential
from asyauth.common.credentials.credssp import CREDSSPCredential
from asyauth.common.constants import asyauthProtocol, asyauthSecret

from asyauth.protocols.ntlm.client.native import NTLMClientNative
from asyauth.protocols.spnego.client.native import SPNEGOClientNative
from asyauth.protocols.credssp.client.native import CredSSPClientNative


class TestBuildContextRecursion(unittest.TestCase):
    """Regression tests for https://github.com/skelsec/asyauth/issues/8

    A UniCredential tagged with a wrapper protocol (CREDSSP/SPNEGO/SPNEGOEX)
    used to recurse forever in build_context() because the inner credential was
    built from ``self`` without changing the protocol.
    """

    def test_issue8_exact_reproduction(self):
        # The exact snippet from issue #8 must not raise RecursionError.
        credentials = UniCredential(
            'foo', 'bar',
            protocol=asyauthProtocol.CREDSSP,
            stype=asyauthSecret.PASSWORD,
        )
        authapi = CREDSSPCredential([credentials])
        ctx = authapi.build_context()
        self.assertIsInstance(ctx, CredSSPClientNative)

    def test_bare_unicredential_wrapper_protocols(self):
        # A plain UniCredential tagged with a wrapper protocol defaults the
        # inner mechanism to NTLM and builds a valid context.
        expected = {
            asyauthProtocol.CREDSSP: CredSSPClientNative,
            asyauthProtocol.SPNEGO: SPNEGOClientNative,
            asyauthProtocol.SPNEGOEX: SPNEGOClientNative,
        }
        for protocol, ctx_type in expected.items():
            cred = UniCredential(
                'pw', 'user', 'domain',
                protocol=protocol,
                stype=asyauthSecret.PASSWORD,
            )
            ctx = cred.build_context()
            self.assertIsInstance(ctx, ctx_type)

    def test_properly_constructed_credentials_still_work(self):
        inner = NTLMCredential('pw', 'user', 'domain', asyauthSecret.PASSWORD)
        self.assertIsInstance(CREDSSPCredential([inner]).build_context(), CredSSPClientNative)
        self.assertIsInstance(SPNEGOCredential([inner]).build_context(), SPNEGOClientNative)

    def test_from_params_wrapper_protocols(self):
        cases = {
            'credssp-ntlm-password': CredSSPClientNative,
            'spnego-ntlm-password': SPNEGOClientNative,
            'spnego-kerberos-password': SPNEGOClientNative,
            'ntlm-password': NTLMClientNative,
        }
        for authproto, ctx_type in cases.items():
            cred = UniCredential.from_params(
                authproto, username='user', domain='domain', secret='pw', dc='1.2.3.4',
            )
            self.assertIsInstance(cred.build_context(), ctx_type)


if __name__ == '__main__':
    unittest.main()
