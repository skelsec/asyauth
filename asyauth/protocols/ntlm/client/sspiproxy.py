from asyauth import logger
from asyauth.protocols.ntlm.client.native import NTLMClientNative
from wsnet.operator.sspiproxy import WSNETSSPIProxy
from asyauth.common.winapi.constants import ISC_REQ

class NTLMClientSSPIProxy:
	def __init__(self, credential):
		self.credential = credential
		url = '%s://%s:%s' % (self.settings.proto, self.settings.host, self.settings.port)
		self.sspi = WSNETSSPIProxy(url, self.settings.agent_id)
		self.iterations = 0
		
		self.session_key = None
		self.ntlm_ctx = NTLMClientNative(self.credential)

	def setup(self):
		return
		
	@property
	def ntlmChallenge(self):
		return self.ntlm_ctx.ntlmChallenge
		
	def get_sealkey(self, mode = 'Client'):
		return self.ntlm_ctx.get_sealkey(mode = mode)
			
	def get_signkey(self, mode = 'Client'):
		return self.ntlm_ctx.get_signkey(mode = mode)
		
		
	def SEAL(self, signingKey, sealingKey, messageToSign, messageToEncrypt, seqNum, cipher_encrypt):
		return self.ntlm_ctx.SEAL(signingKey, sealingKey, messageToSign, messageToEncrypt, seqNum, cipher_encrypt)
		
	def SIGN(self, signingKey, message, seqNum, cipher_encrypt):
		return self.ntlm_ctx.SIGN(signingKey, message, seqNum, cipher_encrypt)
	
	def get_session_key(self):
		return self.session_key
		
	def get_extra_info(self):
		return self.ntlm_ctx.get_extra_info()
		
	def is_extended_security(self):
		return self.ntlm_ctx.is_extended_security()
	
	async def authenticate(self, authData = b'', flags = None, seq_number = 0, is_rpc = False):
		try:
			if is_rpc is True and flags is None:
				flags = ISC_REQ.REPLAY_DETECT | ISC_REQ.CONFIDENTIALITY| ISC_REQ.USE_SESSION_KEY| ISC_REQ.INTEGRITY| ISC_REQ.SEQUENCE_DETECT| ISC_REQ.CONNECTION
			elif flags is None:
				flags = ISC_REQ.CONNECTION

			if authData is None:
				status, ctxattr, data, err = await self.sspi.authenticate('NTLM', '', '', 3, flags.value, authdata = b'')
				if err is not None:
					raise err
				self.iterations += 1
				self.ntlm_ctx.load_negotiate(data)
				return data, True, None
			else:
				self.ntlm_ctx.load_challenge(authData)
				status, ctxattr, data, err = await self.sspi.authenticate('NTLM', '', '', 3, flags.value, authdata = authData)
				if err is not None:
					raise err
				if err is None:
					self.ntlm_ctx.load_authenticate(data)
					self.session_key, err = await self.sspi.get_sessionkey()
					if err is not None:
						raise err
					self.ntlm_ctx.load_sessionkey(self.get_session_key())
				
				await self.sspi.disconnect()
				return data, False, None
		except Exception as e:
			return None, None, e
		
	