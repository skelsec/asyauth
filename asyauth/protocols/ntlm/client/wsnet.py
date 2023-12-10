from asyauth import logger
from asyauth.protocols.ntlm.client.native import NTLMClientNative
from wsnet.pyodide.clientauth import WSNETAuth
from asyauth.common.winapi.constants import ISC_REQ

class NTLMClientWSNET:
	def __init__(self, credential):
		self.credential = credential
		self.sspi = WSNETAuth()
		self.iterations = 0
		
		self.session_key = None
		self.ntlm_ctx = NTLMClientNative(self.credential)

	def setup(self):
		return
		
	@property
	def ntlmChallenge(self):
		return self.ntlm_ctx.ntlmChallenge
	
	def get_seq_number(self):
		return self.ntlm_ctx.seq_number
		
	def get_sealkey(self, mode = 'Client'):
		return self.ntlm_ctx.get_sealkey(mode = mode)
			
	def get_signkey(self, mode = 'Client'):
		return self.ntlm_ctx.get_signkey(mode = mode)
	
	async def encrypt(self, data, sequence_no):
		return await self.ntlm_ctx.encrypt(data, data, sequence_no)

	async def decrypt(self, data, sequence_no, direction='init', auth_data=None):
		return await self.ntlm_ctx.decrypt(data, sequence_no, direction=direction, auth_data=auth_data)

	async def sign(self, data, message_no, direction=None, reset_cipher = False):
		return await self.ntlm_ctx.sign(data, message_no, direction=direction, reset_cipher = reset_cipher)

	async def verify(self, data, signature):
		return await self.ntlm_ctx.verify(data, signature)
		
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
	
	def signing_needed(self):
		return self.ntlm_ctx.signing_needed()
	
	def encryption_needed(self):
		return self.ntlm_ctx.encryption_needed()
		
	async def encrypt(self, data, message_no):
		return await self.ntlm_ctx.encrypt(data, message_no)
		
	async def decrypt(self, data, sequence_no, direction='init', auth_data=None):
		return await self.ntlm_ctx.decrypt(data, sequence_no, direction=direction, auth_data=auth_data)
	
	async def authenticate(self, authData, flags:ISC_REQ = None, cb_data = None, spn=None):
		try:
			if flags is None:
				flags = ISC_REQ.CONNECTION
			#if is_rpc is True and flags is None:
			#	flags = ISC_REQ.REPLAY_DETECT | ISC_REQ.CONFIDENTIALITY| ISC_REQ.USE_SESSION_KEY| ISC_REQ.INTEGRITY| ISC_REQ.SEQUENCE_DETECT| ISC_REQ.CONNECTION
			#elif flags is None:
			#	flags = ISC_REQ.CONNECTION

			if authData is None:
				status, ctxattr, negotiate_raw, err = await self.sspi.authenticate('NTLM', '', '', 3, flags.value, authdata = b'')
				if err is not None:
					raise err
				self.iterations += 1
				self.ntlm_ctx.load_negotiate(negotiate_raw)
				return negotiate_raw, True, None
			else:
				self.ntlm_ctx.load_challenge(authData)
				status, ctxattr, authenticate_raw, err = await self.sspi.authenticate('NTLM', '', '', 3, flags.value, authdata = authData)
				if err is not None:
					raise err
				if err is None:
					self.ntlm_ctx.load_authenticate(authenticate_raw)
					self.session_key, err = await self.sspi.get_sessionkey()
					if err is not None:
						raise err
					self.ntlm_ctx.load_sessionkey(self.get_session_key())
				
				await self.sspi.disconnect()
				return authenticate_raw, False, None
		except Exception as e:
			return None, None, e
		
	