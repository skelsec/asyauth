import os
from asyauth.protocols.ntlm import logger

from asyauth.protocols.ntlm.client.native import NTLMClientNative
from asyauth.common.winapi.constants import ISC_REQ

from wsnet.agent.direct.auth import WSNETDirectAuth


class NTLMClientWSNETDirect:
	def __init__(self, credential):
		self._authid = os.urandom(4).hex()
		self.credential = credential
		self.sspi = None
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
			
			logger.debug('[WSNETDirect][NTLM][%s] spn: %s' % (self._authid, spn))
			logger.debug('[WSNETDirect][NTLM][%s] flags: %s' % (self._authid, flags))
			logger.debug('[WSNETDirect][NTLM][%s] cb_data: %s' % (self._authid, cb_data))
			
			if self.sspi is None:
				self.sspi = WSNETDirectAuth(self.credential.subprotocol.get_url())
				_, err = await self.sspi.connect()
				if err is not None:
					raise err
				
			if authData is None:
				logger.debug('[WSNETDirect][NTLM][%s] Initializing auth context, fetching Negotaite' % self._authid)
				status, ctxattr, negotiate_raw, err = await self.sspi.authenticate('NTLM', '', '', 3, flags.value, authdata = b'')
				if err is not None:
					raise err
				logger.debug('[WSNETDirect][NTLM][%s][Response] Status: %s' % (self._authid, status))
				logger.debug('[WSNETDirect][NTLM][%s][Response] Response flags: %s' % (self._authid, ctxattr))
				logger.debug('[WSNETDirect][NTLM][%s][Response] Negotiate: %s' % (self._authid, negotiate_raw))
				self.iterations += 1
				self.ntlm_ctx.load_negotiate(negotiate_raw)
				return negotiate_raw, True, None
			else:
				logger.debug('[WSNETDirect][NTLM][%s] Challenge: %s' % (self._authid, authData))
				self.ntlm_ctx.load_challenge(authData)
				logger.debug('[WSNETDirect][NTLM][%s] Sending Challenge, getting Authenticate...' % self._authid)
				status, ctxattr, authenticate_raw, err = await self.sspi.authenticate('NTLM', '', '', 3, flags.value, authdata = authData)
				if err is not None:
					raise err
				
				self.ntlm_ctx.load_authenticate(authenticate_raw)
				logger.debug('[WSNETDirect][NTLM][%s][Response] Status: %s' % (self._authid, status))
				logger.debug('[WSNETDirect][NTLM][%s][Response] Response flags: %s' % (self._authid, ctxattr))
				logger.debug('[WSNETDirect][NTLM][%s][Response] Authenticate: %s' % (self._authid, authenticate_raw))

				logger.debug('[WSNETDirect][NTLM][%s] Fetching SessionKey...' % self._authid)
				self.session_key, err = await self.sspi.get_sessionkey()
				if err is not None:
					raise err
				
				logger.debug('[WSNETDirect][NTLM][%s][Response] SessionKey: %s' % (self._authid, self.session_key.hex()))
				self.ntlm_ctx.load_sessionkey(self.get_session_key())
				
				logger.debug('[WSNETDirect][NTLM][%s][NTLMINFO] %s' % (self._authid, self.ntlm_ctx.get_extra_info()))

				await self.sspi.disconnect()
				return authenticate_raw, False, None
		except Exception as e:
			return None, None, e
		
	