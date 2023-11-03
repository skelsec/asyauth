# This is working, but also a work in progress!!!

from asyauth.protocols.spnego.messages.asn1_structs import *
import asyncio
from typing import Callable

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/d4f2b41c-5f9e-4e11-98d0-ade76467095d


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/94ccc4f8-d224-495f-8d31-4f58d1af598e
## SPNEGO has been assigned the following object identifier (OID): so.org.dod.internet.security.mechanism.snego (1.3.6.1.5.5.2)

class SPNEGORelay:
	def __init__(self, auth_relay_queue:asyncio.Queue):
		self.auth_relay_queue = auth_relay_queue
		self.authentication_contexts = {}
		self.selected_authentication_context = None
		self.selected_authentication_context_server = None
		self.selected_mechtype = None
		self.selected_mechtype_server = None
		self.iteration_ctr = 0
		self.start_client_evt = None
		self.iteration_ctr_server = 0
		self.mic_data = None
		self.__server_side_crash = None
		self.__client_side_crash = None
		self.__server_latest_token = None
		self.__relay_queue_notified = False
		self.__authtype = None
	
	def setup(self, log_q = None):
		for k in self.authentication_contexts:
			self.authentication_contexts[k].setup(log_q)
			self.start_client_evt = self.authentication_contexts[k].start_client_evt
	
	async def notify_relay(self, authtype = None):
		if self.__relay_queue_notified is False:
			self.__authtype = authtype
			await self.auth_relay_queue.put(self)
			self.__relay_queue_notified = True

	def is_guest(self):
		if self.selected_authentication_context is None:
			raise Exception('Call this after selecting auth method!')
		
		if hasattr(self.selected_authentication_context, 'is_guest') is True:
			return self.selected_authentication_context.is_guest()
		return False

	async def sign(self, data, message_no, direction='init'):
		return await self.selected_authentication_context.sign(data, message_no, direction=direction)
		
	async def encrypt(self, data, message_no):
		return await self.selected_authentication_context.encrypt(data, message_no)

	async def decrypt(self, data, message_no, direction='init', auth_data=None):
		return await self.selected_authentication_context.decrypt(data, message_no, direction=direction, auth_data=auth_data)
	
	def get_ntlm(self):
		if 'NTLMSSP - Microsoft NTLM Security Support Provider' in self.authentication_contexts:
			return self.authentication_contexts['NTLMSSP - Microsoft NTLM Security Support Provider']
		return None
		
	def add_auth_context(self, name, ctx):
		"""
		Add an authentication context to the given authentication context name.
		Valid names are:
			'NTLMSSP - Microsoft NTLM Security Support Provider'
			'MS KRB5 - Microsoft Kerberos 5'
			'KRB5 - Kerberos 5'
			'KRB5 - Kerberos 5 - User to User'
			'NEGOEX - SPNEGO Extended Negotiation Security Mechanism'
			
		Context MUST be already set up!
		"""
		self.authentication_contexts[name] = ctx
		
	def select_common_athentication_type(self, mech_types):
		for auth_type_name in self.authentication_contexts:
			if auth_type_name in mech_types:
				return auth_type_name, self.authentication_contexts[auth_type_name]
				
		return None, None
	
	async def process_ctx_authenticate_server(self, token_data, include_negstate = False, flags = None, seq_number = 0, is_rpc = False):
		result, to_continue, err = await self.selected_authentication_context_server.authenticate_relay_server(token_data)
		if err is not None:
			return None, None, err
		if result is None:
			return None, False, None
		response = {}
		if include_negstate == True:
			if to_continue == True:
				response['negState'] = NegState('accept-incomplete')
			else:
				response['negState'] = NegState('accept-completed')
		
		if result is not None and len(result) > 0:
			response['responseToken'] = result
		return response, to_continue, None
		
	async def process_ctx_authenticate(self, token_data, *args, **kwargs):
		result, to_continue, err = await self.selected_authentication_context.authenticate(token_data, *args, **kwargs)
		if err is not None:
			return None, None, err
		if not result:
			return None, False, None
		response = {}		
		response['responseToken'] = result
		return response, to_continue, None
	
	def get_copy(self):
		return self
	
	def list_original_conexts(self):
		"""
		Returns a list of authentication context names available to the SPNEGO authentication.
		"""
		return list(self.authentication_contexts.keys())
	
	def get_original_context(self, ctx_name):
		"""
		Returns a copy of the original (not used) authentication context sp[ecified by name.
		You may use this ctx to perform future authentication, as it has the user credentials
		"""
		return self.authentication_contexts[ctx_name]

	def get_extra_info(self):
		if hasattr(self.selected_authentication_context, 'get_extra_info'):
			return self.selected_authentication_context.get_extra_info()
		return None
	
	def get_session_key(self):
		return self.selected_authentication_context.get_session_key()

	def get_mechtypes_list(self):
		neghint = {'hintName':'not_defined_in_RFC4178@please_ignore'}
		tokinit = {
			'mechTypes': [MechType(mt) for mt in self.authentication_contexts],
			'negHints': NegHints(neghint),
		}

		negtoken = NegotiationToken({'negTokenInit':NegTokenInit2(tokinit)})
		#spnego = GSS_SPNEGO({'NegotiationToken':negtoken})
		return GSSAPI({'type': GSSType('1.3.6.1.5.5.2'), 'value':negtoken}).dump()
	
	async def authenticate_relay_server(self, token, flags = None, seq_number = 0, is_rpc = False):
		self.__server_latest_token = token
		try:
			if self.__client_side_crash is not None:
				return None, False, Exception('Client auth crashed!')
			negtoken = None
			if self.selected_authentication_context_server is None:
				gss = GSSAPI.load(token).native
				negtoken = gss['value']
				if len(negtoken['mechTypes']) == 1:
					self.selected_mechtype_server = negtoken['mechTypes'][0]
					if negtoken['mechTypes'][0] == 'NTLMSSP - Microsoft NTLM Security Support Provider':
						await self.notify_relay() # something is happening here!
						self.selected_authentication_context_server = self.authentication_contexts[negtoken['mechTypes'][0]]


				else:
					raise Exception('This path is not yet implemented')

			if self.selected_authentication_context_server is not None:
				if negtoken is None:
					if token[0] == 0x60:
						gss = GSSAPI.load(token).native
						negtoken = gss['value']
					else:
						neg_token_raw = NegotiationToken.load(token)
						negtoken = neg_token_raw.native
				if 'mechToken' in negtoken:
					authdata = negtoken['mechToken']
				else:
					authdata = negtoken['responseToken']
				if 'mechListMIC' in negtoken:
					self.mic_data = negtoken['mechListMIC']
				response, to_continue, err = await self.process_ctx_authenticate_server(authdata, flags = flags, seq_number = seq_number, is_rpc = is_rpc, include_negstate = True)
				if err is not None:
					return None, None, err

				if response is None:
					return None, False, None
				if self.iteration_ctr_server == 0:
					response['supportedMech'] = MechType(self.selected_mechtype_server)
					negtoken = NegotiationToken({'negTokenResp':NegTokenResp(response)})
				if self.iteration_ctr_server == 1:
					negtoken = NegotiationToken({
						'negTokenResp' : NegTokenResp(response),
					})

				
				self.iteration_ctr_server += 1
				return negtoken.dump(), to_continue, None
		except Exception as e:
			self.__server_side_crash = e
			return None, False, e
	
	
	async def authenticate(self, token, *args, **kwargs): #seq_number = 0, is_rpc = False):
		"""
		This function is called (multiple times) during negotiation phase of a protocol to determine hich auth mechanism to be used
		Token is a byte array that is an ASN1 NegotiationToken structure.
		"""
		try:
			if self.__server_side_crash is not None:
				return None, False, Exception('Server auth crashed!')
			if self.selected_mechtype is None:
				if token is None:
					#first call to auth, we need to create NegTokenInit2
					#we must list all available auth types, if only one is present then generate initial auth data with it
					
					selected_name = None
					mechtypes = []
					for mechname in self.authentication_contexts:
						selected_name = mechname #only used if there is one!
						mechtypes.append(MechType(mechname))
					
					response = {}
					response['mechTypes'] = MechTypes(mechtypes)
					
					if len(mechtypes) == 1:
						self.selected_authentication_context = self.authentication_contexts[selected_name]
						self.selected_mechtype = selected_name
						result, to_continue, err = await self.selected_authentication_context.authenticate(None, *args, **kwargs)
						if err is not None:
							return None, None, err
						response['mechToken'] = result
						#if is_rpc == False:
						#	response['mechToken'] = result
						#else:
						#	if not result:
						#		return None, False, None
						#	if str(response['mechTypes'][0]) == '1.2.840.48018.1.2.2':
						#		response['mechToken'] = KRB5Token(result).to_bytes()
						#	else:
						#		raise Exception('NTLM as RPC GSSAPI not implemented!')
					
					### First message and ONLY the first message goes out with additional wrapping
					
					negtoken = NegotiationToken({'negTokenInit':NegTokenInit2(response)})
					
					
					#spnego = GSS_SPNEGO({'NegotiationToken':negtoken})
					return GSSAPI({'type': GSSType('1.3.6.1.5.5.2'), 'value':negtoken}).dump(), True, None
					
					
				else:
					#we have already send the NegTokenInit2, but it contained multiple auth types,
					#at this point server is replying which auth type to use
					neg_token_raw = NegotiationToken.load(token)
					neg_token = neg_token_raw.native
					
					if not isinstance(neg_token_raw, NegTokenResp):
						raise Exception('Server send init???')
						
					self.selected_authentication_context = self.authentication_contexts[neg_token.mechTypes[0]]
					self.selected_mechtype = neg_token['supportedMech']
	
					response, to_continue, err = await self.process_ctx_authenticate(neg_token['responseToken'], *args, **kwargs)
					if err is not None:
						return None, None, err
					return NegTokenResp(response).dump(), to_continue, None
					
			else:
				neg_token_raw = NegotiationToken.load(token)
				neg_token = neg_token_raw.native
				if neg_token['negState'] == 'accept-completed':
					return None, False, None
				if neg_token['responseToken'] is None:
					# https://tools.ietf.org/html/rfc4178#section-5
					# mechlistmic exchange happening at the end of the authentication
					print('!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!111111111111')
					#print(neg_token_raw.native)
					#return self.__server_latest_token, True, None
					return None, True, None
				
				else:
					
					response, to_continue, err = await self.process_ctx_authenticate(neg_token['responseToken'], *args, **kwargs)
					if err is not None:
						return None, None, err
					if not response:
						return None, False, None

					#if self.selected_mechtype.startswith('NTLM'):
					#	response['mechListMIC'] = await self.sign(self.negtypes_store, 0, reset_cipher = True)
					#	self.internal_seq += 1
					res = NegotiationToken({'negTokenResp':NegTokenResp(response)}).dump()

					if self.__authtype is None:
						return self.__server_latest_token, True, None
					else:
						return res, to_continue, None
					#return res, to_continue, None
			
				##everything is netotiated, but authentication needs more setps
				#neg_token_raw = NegotiationToken.load(token)
				#neg_token = neg_token_raw.native
				#if neg_token['negState'] == 'accept-completed' and neg_token['responseToken'] is None:
				#	return None, True, None
				#response, to_continue, err = await self.process_ctx_authenticate(neg_token['responseToken'], flags = flags, seq_number = seq_number, is_rpc = is_rpc)
				#if err is not None:
				#	return None, None, err
				#if not response:
				#	return None, False, None
				#
				#if self.mic_data is not None:
				#	response['mechListMIC'] = self.mic_data
				#return NegotiationToken({'negTokenResp':NegTokenResp(response)}).dump(), to_continue, None
		except Exception as e:
			self.__client_side_crash = e
			return None, False, e

def spnegorelay_ntlm_factory(auth_relay_queue:asyncio.Queue, ntlm_handler_factory: Callable = None) -> SPNEGORelay:
	ntlm_ctx = ntlm_handler_factory()
	gssapi = SPNEGORelay(auth_relay_queue)
	gssapi.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', ntlm_ctx)
	ntlm_ctx.spnego_obj = gssapi
	return gssapi