import asyncio
import unittest

from asyauth.common.constants import (
	asyauthProtocol,
	asyauthSecret,
	asyauthSubProtocol,
)
from asyauth.common.credentials import UniCredential
from asyauth.common.credentials.ntlm import NTLMCredential
from asyauth.common.credentials.spnego import SPNEGOCredential
from asyauth.common.subprotocols import SubProtocol
from asyauth.protocols.ntlm.server.native import ntlmserver_factory
from asyauth.protocols.ntlm.messages.authenticate import NTLMAuthenticate
from asyauth.protocols.ntlm.messages.challenge import NTLMChallenge
from asyauth.protocols.ntlm.structures.negotiate_flags import NegotiateFlags
from asyauth.protocols.spnego.server.native import spnegoserver_ntlm_factory


class TestNTLMAnonymousCredential(unittest.TestCase):
	def test_url_parses_ntlm_none_as_anonymous(self):
		credential = UniCredential.from_url(
			'smb2+ntlm-none://files.example/Public'
		)

		self.assertEqual(credential.protocol, asyauthProtocol.NTLM)
		self.assertEqual(credential.stype, asyauthSecret.NONE)
		self.assertEqual(credential.username, '')
		self.assertEqual(credential.domain, '')
		self.assertIsNone(credential.secret)
		self.assertTrue(credential.is_anonymous)
		self.assertTrue(credential.is_guest)

	def test_from_params_parses_ntlm_none(self):
		credential = UniCredential.from_params('ntlm-none')

		self.assertEqual(credential.stype, asyauthSecret.NONE)
		self.assertTrue(credential.is_anonymous)

	def test_named_native_ntlm_none_is_rejected(self):
		with self.assertRaises(ValueError):
			NTLMCredential(
				None,
				'alice',
				'LAB',
				stype=asyauthSecret.NONE,
			)

	def test_create_guest_remains_an_anonymous_alias(self):
		credential = NTLMCredential.create_guest()

		self.assertTrue(credential.is_anonymous)
		self.assertEqual(credential.stype, asyauthSecret.NONE)

	def test_named_empty_password_remains_password_authentication(self):
		credential = NTLMCredential(
			'',
			'alice',
			'LAB',
			stype=asyauthSecret.PASSWORD,
		)

		self.assertEqual(credential.stype, asyauthSecret.PASSWORD)
		self.assertFalse(credential.is_anonymous)

	def test_hash_credentials_remain_authenticated(self):
		credential = NTLMCredential(
			'8846f7eaee8fb117ad06bdd830b7586c',
			'alice',
			'LAB',
			stype=asyauthSecret.NT,
		)

		self.assertEqual(credential.stype, asyauthSecret.NT)
		self.assertFalse(credential.is_anonymous)

	def test_sspi_none_does_not_gain_native_anonymous_semantics(self):
		credential = NTLMCredential(
			None,
			None,
			None,
			stype=asyauthSecret.NONE,
			subprotocol=SubProtocol(asyauthSubProtocol.SSPI),
		)

		self.assertFalse(credential.is_anonymous)

	def test_url_can_disable_extended_session_security(self):
		credential = UniCredential.from_url(
			'smb2+ntlm-password://LAB\\alice:secret@files.example'
			'/?ntlmdisableess=1'
		)

		self.assertTrue(credential.disable_ess)


class TestNTLMAnonymousExchange(unittest.IsolatedAsyncioTestCase):
	async def test_native_exchange_emits_null_authenticate_fields(self):
		credential = NTLMCredential.create_anonymous()
		client = credential.build_context()
		server = ntlmserver_factory(NTLMCredential.create_anonymous)

		negotiate, more, error = await client.authenticate(None)
		self.assertIsNone(error)
		self.assertTrue(more)
		challenge, more, error = await server.authenticate_server(negotiate)
		self.assertIsNone(error)
		self.assertTrue(more)

		authenticate, more, error = await client.authenticate(challenge)
		self.assertIsNone(error)
		self.assertFalse(more)
		self.assertTrue(client.is_anonymous())
		self.assertEqual(
			int.from_bytes(authenticate[12:14], 'little'),
			1,
		)
		self.assertEqual(
			int.from_bytes(authenticate[20:22], 'little'),
			0,
		)
		self.assertEqual(
			int.from_bytes(authenticate[28:30], 'little'),
			0,
		)
		self.assertEqual(
			int.from_bytes(authenticate[36:38], 'little'),
			0,
		)
		self.assertEqual(
			int.from_bytes(authenticate[44:46], 'little'),
			0,
		)
		lm_offset = int.from_bytes(authenticate[16:20], 'little')
		self.assertEqual(authenticate[lm_offset:lm_offset + 1], b'\x00')
		flags = NegotiateFlags(
			int.from_bytes(authenticate[60:64], 'little')
		)
		self.assertIn(NegotiateFlags.J, flags)
		self.assertNotIn(NegotiateFlags.NEGOTIATE_VERSION, flags)

		response, more, error = await server.authenticate_server(authenticate)
		self.assertIsNone(response)
		self.assertIsNone(error)
		self.assertFalse(more)

	async def test_anonymous_authenticate_ignores_server_hostname(self):
		from asysocks.unicomm.common.target import UniProto, UniTarget

		server_target = UniTarget('dc01.lab.local', 445, UniProto.CLIENT_TCP)
		self.assertEqual(server_target.hostname, 'dc01.lab.local')

		credential = NTLMCredential.create_anonymous()
		client = credential.build_context()
		server = ntlmserver_factory(NTLMCredential.create_anonymous)

		negotiate, more, error = await client.authenticate(None)
		self.assertIsNone(error)
		self.assertTrue(more)
		challenge, more, error = await server.authenticate_server(negotiate)
		self.assertIsNone(error)
		self.assertTrue(more)

		authenticate, more, error = await client.authenticate(
			challenge,
			target=server_target,
		)
		self.assertIsNone(error)
		self.assertFalse(more)
		parsed = NTLMAuthenticate.from_bytes(authenticate)
		self.assertIn(parsed.Workstation, (None, ''))
		self.assertEqual(
			int.from_bytes(authenticate[44:46], 'little'),
			0,
		)

	async def test_spnego_delegates_anonymous_state(self):
		credential = NTLMCredential.create_anonymous()
		client = SPNEGOCredential([credential]).build_context()
		server = spnegoserver_ntlm_factory(
			asyncio.Queue(),
			lambda: ntlmserver_factory(NTLMCredential.create_anonymous),
		)

		token, more, error = await client.authenticate(None)
		self.assertIsNone(error)
		self.assertTrue(more)
		challenge, more, error = await server.authenticate_server(token)
		self.assertIsNone(error)
		self.assertTrue(more)
		token, more, error = await client.authenticate(challenge)
		self.assertIsNone(error)
		self.assertFalse(more)
		response, more, error = await server.authenticate_server(token)
		self.assertIsNone(response)
		self.assertIsNone(error)
		self.assertFalse(more)
		self.assertTrue(client.is_anonymous())
		self.assertTrue(server.is_anonymous())


class TestNTLMServerPolicy(unittest.IsolatedAsyncioTestCase):
	async def test_disable_ess_clears_only_the_challenge_capability(self):
		client_credential = NTLMCredential(
			'secret',
			'alice',
			'LAB',
			stype=asyauthSecret.PASSWORD,
		)
		server_credential = NTLMCredential(
			'secret',
			'alice',
			'LAB',
			stype=asyauthSecret.PASSWORD,
			ntlmdisableess=True,
		)
		client = client_credential.build_context()
		server = ntlmserver_factory(lambda: server_credential)

		negotiate, more, error = await client.authenticate(None)
		self.assertIsNone(error)
		self.assertTrue(more)
		challenge, more, error = await server.authenticate_server(negotiate)
		self.assertIsNone(error)
		self.assertTrue(more)

		parsed = NTLMChallenge.from_bytes(challenge)
		self.assertNotIn(
			NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY,
			parsed.NegotiateFlags,
		)
		self.assertIn(
			NegotiateFlags.NEGOTIATE_TARGET_INFO,
			parsed.NegotiateFlags,
		)
		self.assertIsNotNone(parsed.TargetInfo)

		authenticate, more, error = await client.authenticate(challenge)
		self.assertIsNone(error)
		self.assertFalse(more)
		parsed_authenticate = NTLMAuthenticate.from_bytes(authenticate)
		self.assertNotIn(
			NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY,
			parsed_authenticate.NegotiateFlags,
		)


if __name__ == '__main__':
	unittest.main()
