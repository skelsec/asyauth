# This is working, but also a work in progress!!!

from asyauth.protocols.spnego.messages.asn1_structs import *
import asyncio
from typing import Callable

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/d4f2b41c-5f9e-4e11-98d0-ade76467095d


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/94ccc4f8-d224-495f-8d31-4f58d1af598e
## SPNEGO has been assigned the following object identifier (OID): so.org.dod.internet.security.mechanism.snego (1.3.6.1.5.5.2)

class SPNEGOserver:
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
		self.__authtype = None
		self.connection_info = None
		self.original_mechtypes = []

	async def print_debug(self, message):
		print('[SPNEGOServer] %s' % message)
	
	def setup(self, log_q = None):
		for k in self.authentication_contexts:
			self.authentication_contexts[k].setup(log_q)
			self.start_client_evt = self.authentication_contexts[k].start_client_evt

	def set_connection_info(self, connection_info):
		self.connection_info = connection_info
		
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
		result, to_continue, err = await self.selected_authentication_context_server.authenticate_server(token_data)
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

	async def authenticate_server_finished(self):
		# sending accept-completed to the client
		response = {}
		response['negState'] = NegState('accept-completed')
		return NegotiationToken({'negTokenResp':NegTokenResp(response)}).dump(), None
		
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
	
	async def authenticate_server(self, token, flags = None, seq_number = 0, is_rpc = False):
		self.__server_latest_token = token
		try:
			negtoken = None
			if self.selected_authentication_context_server is None:
				gss = GSSAPI.load(token).native
				negtoken = gss['value']
				if len(negtoken['mechTypes']) == 1:
					self.selected_mechtype_server = negtoken['mechTypes'][0]
					if negtoken['mechTypes'][0] == 'NTLMSSP - Microsoft NTLM Security Support Provider':
						self.selected_authentication_context_server = self.authentication_contexts[negtoken['mechTypes'][0]]


				else:
					for mechtype in negtoken['mechTypes']:
						if mechtype == 'NTLMSSP - Microsoft NTLM Security Support Provider':
							self.selected_mechtype_server = mechtype
							self.selected_authentication_context_server = self.authentication_contexts[mechtype]
							break
					if self.selected_authentication_context_server is None:
						await self.print_debug('[DEBUG][MULTIPLE_MECHTYPES] negtoken: %s' % negtoken)
						raise Exception('Failed to find NTLM in mechtypes: %s' % negtoken['mechTypes'])

			if self.selected_authentication_context_server is not None:
				if negtoken is None:
					if token[0] == 0x60:
						gss = GSSAPI.load(token).native
						negtoken = gss['value']
					else:
						try:
							neg_token_raw = NegotiationToken.load(token)
							negtoken = neg_token_raw.native
						except Exception as e:
							await self.print_debug('[DEBUG][NEGTOKEN_LOAD_ERROR] %s' % token)
							print('[DEBUG][NEGTOKEN_LOAD_ERROR] %s' % e)
							raise e
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

def spnegoserver_ntlm_factory(auth_relay_queue:asyncio.Queue, ntlm_handler_factory: Callable = None) -> SPNEGOserver:
	ntlm_ctx = ntlm_handler_factory()
	gssapi = SPNEGOserver(auth_relay_queue)
	gssapi.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', ntlm_ctx)
	ntlm_ctx.spnego_obj = gssapi
	return gssapi