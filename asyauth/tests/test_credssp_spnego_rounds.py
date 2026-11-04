import asyncio
import unittest
from hashlib import sha256
from types import SimpleNamespace

from asyauth.common.constants import asyauthSecret
from asyauth.protocols.credssp.client.native import CredSSPClientNative
from asyauth.protocols.credssp.messages.asn1_structs import NegoData, NegoDatas, TSRequest
from asyauth.protocols.spnego.client.native import SPNEGOClientNative
from asyauth.protocols.spnego.messages.asn1_structs import NegotiationToken, NegTokenResp


PUBKEY = b'\x30' + b'K' * 40
CLIENT_PUBKEYAUTH = b'C' * 16 + b'c' * 32
SERVER_PUBKEYAUTH = b'S' * 16 + b's' * 32


class StubSPNEGO:
	"""Stands in for SPNEGOClientNative under CredSSP: two legs, then sealing."""
	def __init__(self):
		self.decrypted = []

	async def authenticate(self, token, flags=None, spn=None):
		if token is None:
			return b'NEGOTIATE', True, None
		return b'AUTHENTICATE', False, None

	def get_internal_seq(self):
		return 1

	async def encrypt(self, data, seqno):
		if data.startswith(b'CredSSP Client-To-Server'):
			raise AssertionError('hash must be passed hashed')
		return CLIENT_PUBKEYAUTH[16:], CLIENT_PUBKEYAUTH[:16]

	async def decrypt(self, data, seqno):
		self.decrypted.append(data)
		return self.server_hash, None

	def get_active_credential(self):
		return SimpleNamespace(stype=asyauthSecret.NONE)


def ts_request(**fields):
	return TSRequest({'version': 6, **fields}).dump()


def nego(token):
	return NegoDatas([NegoData({'negoToken': token})])


class TestCredSSPFinalSpnegoRound(unittest.TestCase):
	def setUp(self):
		self.ctx = CredSSPClientNative(credential=None)
		self.ctx.auth_ctx = StubSPNEGO()
		self.ctx._CredSSPClientNative__pubkey = PUBKEY
		self.ctx.auth_ctx.server_hash = sha256(
			b'CredSSP Server-To-Client Binding Hash\x00' + self.ctx.nonce + PUBKEY
		).digest()

	def run_steps(self, *server_tokens):
		async def steps():
			out = [await self.ctx.authenticate(None)]
			for token in server_tokens:
				out.append(await self.ctx.authenticate(token))
			return out
		return asyncio.run(steps())

	def test_resends_pubkeyauth_when_server_sends_final_spnego_token_separately(self):
		challenge = ts_request(negoTokens=nego(b'CHALLENGE'))
		# winpr: final SPNEGO token (mechListMIC) with our own pubKeyAuth echoed back
		mic_only = ts_request(negoTokens=nego(b'MIC'), pubKeyAuth=CLIENT_PUBKEYAUTH)
		final = ts_request(pubKeyAuth=SERVER_PUBKEYAUTH)

		results = self.run_steps(challenge, mic_only, final)
		for _, _, err in results:
			self.assertIsNone(err)

		auth_msg = TSRequest.load(results[1][0]).native
		self.assertEqual(auth_msg['pubKeyAuth'], CLIENT_PUBKEYAUTH)

		resent = TSRequest.load(results[2][0]).native
		self.assertTrue(results[2][1])
		self.assertIsNone(resent['negoTokens'])
		self.assertEqual(resent['pubKeyAuth'], CLIENT_PUBKEYAUTH)
		self.assertEqual(resent['clientNonce'], self.ctx.nonce)

		self.assertEqual(self.ctx.auth_ctx.decrypted, [SERVER_PUBKEYAUTH])
		self.assertIsNotNone(TSRequest.load(results[3][0]).native['authInfo'])
		self.assertFalse(results[3][1])

	def test_combined_final_token_and_pubkeyauth_is_verified_directly(self):
		# Windows: final SPNEGO token and the server's pubKeyAuth in one message
		challenge = ts_request(negoTokens=nego(b'CHALLENGE'))
		final = ts_request(negoTokens=nego(b'MIC'), pubKeyAuth=SERVER_PUBKEYAUTH)

		results = self.run_steps(challenge, final)
		self.assertIsNone(results[2][2])
		self.assertEqual(self.ctx.auth_ctx.decrypted, [SERVER_PUBKEYAUTH])
		self.assertIsNotNone(TSRequest.load(results[2][0]).native['authInfo'])

	def test_pubkeyauth_is_resent_only_once(self):
		challenge = ts_request(negoTokens=nego(b'CHALLENGE'))
		mic_only = ts_request(negoTokens=nego(b'MIC'), pubKeyAuth=CLIENT_PUBKEYAUTH)

		results = self.run_steps(challenge, mic_only, mic_only)
		self.assertIsNone(results[2][2])
		self.assertEqual(TSRequest.load(results[2][0]).native['pubKeyAuth'], CLIENT_PUBKEYAUTH)
		# the second one goes to verification instead of looping
		self.assertEqual(self.ctx.auth_ctx.decrypted, [CLIENT_PUBKEYAUTH])
		self.assertIsNone(TSRequest.load(results[3][0]).native['pubKeyAuth'])


class TestSPNEGOClientNegState(unittest.TestCase):
	def test_neg_token_resp_carries_accept_incomplete(self):
		spnego = SPNEGOClientNative.__new__(SPNEGOClientNative)

		class Mech:
			async def authenticate(self, token, *args, **kwargs):
				return b'NTLMSSP-AUTH', False, None

		spnego.selected_authentication_context = Mech()
		response, to_continue, err = asyncio.run(spnego.process_ctx_authenticate(b'challenge'))
		self.assertIsNone(err)
		token = NegotiationToken.load(NegotiationToken({'negTokenResp': NegTokenResp(response)}).dump()).native
		self.assertEqual(token['negState'], 'accept-incomplete')
		self.assertEqual(token['responseToken'], b'NTLMSSP-AUTH')


if __name__ == '__main__':
	unittest.main()
