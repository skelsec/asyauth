from asyauth.common.winapi.winsspi import WinSSPI, SSPIPackage
from asyauth.common.winapi.constants import ISC_REQ, SSPIResult
from asyauth.protocols.ntlm.client.native import NTLMClientNative
from asyauth.common.credentials.ntlm import NTLMCredential

class NTLMClientSSPI:
	def __init__(self, credential:NTLMCredential):
		self.credential = credential
		self.sspi = WinSSPI(SSPIPackage.NTLM)
		self.session_key = None
		self.ntlm_ctx = NTLMClientNative(self.credential)
		self.flags = ISC_REQ.CONNECTION

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
		if not self.session_key:
			self.session_key = self.sspi.get_session_key()
		
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
	
	async def authenticate(self, authData = None, flags = None, seq_number = 0, spn = None, cb_data = None):
		to_continue = False
		if flags is None:
			flags = self.flags
		
		if authData is None:
			self.sspi.acquire_handle(None, spn) #self.credential.username
			result, data, self.flags, expiry = self.sspi.initialize_context(spn, authData, flags=flags, cb_data=cb_data)
			if result == SSPIResult.CONTINUE:
				to_continue = True
			self.ntlm_ctx.load_negotiate(data)
			return data, to_continue, None
		else:
			self.ntlm_ctx.load_challenge(authData)
			result, data, self.flags, expiry = self.sspi.initialize_context(spn, authData, flags=flags, cb_data=cb_data)
			if result == SSPIResult.CONTINUE:
				to_continue = True
		
			self.ntlm_ctx.load_authenticate(data)
			self.ntlm_ctx.load_sessionkey(self.get_session_key())
			
			return data, to_continue, None
			
	