#!/usr/bin/env python3
#
# Author:
#  Tamas Jos (@skelsec)
#

import copy
from asyauth.common.constants import asyauthProtocol
from asyauth.protocols.spnego.messages.asn1_structs import *
from asyauth.common.credentials.spnego import SPNEGOCredential

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/d4f2b41c-5f9e-4e11-98d0-ade76467095d


# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/94ccc4f8-d224-495f-8d31-4f58d1af598e
## SPNEGO has been assigned the following object identifier (OID): so.org.dod.internet.security.mechanism.snego (1.3.6.1.5.5.2)

class SPNEGOClientNative:
	def __init__(self, credential:SPNEGOCredential):
		self.credential = credential

		self.authentication_contexts = {}
		self.original_authentication_contexts = {}
		self.selected_authentication_context_name = None
		self.selected_authentication_context = None
		self.selected_mechtype = None
		self.iteration_ctr = 0
		self.internal_seq = 0
	
	def get_copy(self):
		return self.credential.build_context()

	def get_internal_seq(self):
		return self.internal_seq
		
	def list_original_conexts(self):
		"""
		Returns a list of authentication context names available to the SPNEGO authentication.
		"""
		return list(self.original_authentication_contexts.keys())
		
	def get_original_context(self, ctx_name):
		"""
		Returns a copy of the original (not used) authentication context specified by name.
		You may use this ctx to perform future authentication, as it has the user credentials
		"""
		return copy.deepcopy(self.original_authentication_contexts[ctx_name])

	def get_active_credential(self):
		if self.selected_authentication_context_name is None:
			raise Exception('No authentication context selected!')
		for credential in self.credential.credentials:
			if self.selected_authentication_context_name == 'NTLMSSP - Microsoft NTLM Security Support Provider' and credential.protocol == asyauthProtocol.NTLM:
				return credential
			elif self.selected_authentication_context_name == 'MS KRB5 - Microsoft Kerberos 5' and credential.protocol == asyauthProtocol.KERBEROS:
				return credential
			else:
				raise Exception('Could not identify correct credentials!')
	
	def is_guest(self):
		if self.selected_authentication_context is None:
			raise Exception('Call this after selecting auth method!')
		
		if hasattr(self.selected_authentication_context, 'is_guest') is True:
			return self.selected_authentication_context.is_guest()
		return False
	
	def signing_needed(self):
		return self.selected_authentication_context.signing_needed()
	
	def encryption_needed(self):
		return self.selected_authentication_context.encryption_needed()

	def get_seq_number(self):
		return self.selected_authentication_context.get_seq_number()

	async def unsign(self, data):
		#TODO: IMPLEMENT THIS
		return data

	async def verify(self, data, signature):
		return await self.selected_authentication_context.verify(data, signature)

	async def sign(self, data, message_no, direction='init', reset_cipher = False):
		return await self.selected_authentication_context.sign(data, message_no, direction=direction, reset_cipher = reset_cipher)
		
	async def encrypt(self, data, message_no, *args, **kwargs):
		return await self.selected_authentication_context.encrypt(data, message_no, *args, **kwargs)

	async def decrypt(self, data, message_no, *args, **kwargs):
		return await self.selected_authentication_context.decrypt(data, message_no, *args, **kwargs)
		
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
		self.original_authentication_contexts[name] = self._deep_copy_context(ctx)

	def _deep_copy_context(self, ctx):
		"""
		Create a deep copy of the context, excluding the RSAPrivateKey object which is not serializable.
		"""
		if hasattr(ctx, 'ccred') and hasattr(ctx.ccred, 'private_key'):
			private_key = ctx.ccred.private_key
			ctx.ccred.private_key = None
			new_ctx = copy.deepcopy(ctx)
			ctx.ccred.private_key = private_key
			new_ctx.ccred.private_key = private_key
		else:
			new_ctx = copy.deepcopy(ctx)
			return new_ctx
		
	def select_common_athentication_type(self, mech_types):
		for auth_type_name in self.authentication_contexts:
			if auth_type_name in mech_types:
				return auth_type_name, self.authentication_contexts[auth_type_name]
				
		return None, None
		
	async def process_ctx_authenticate(self, token_data, *args, **kwargs):
		result, to_continue, err = await self.selected_authentication_context.authenticate(token_data, *args, **kwargs)
		if err is not None:
			return None, None, err
		if not result:
			return None, False, None
		response = {}
		#if include_negstate == True:
		#	if to_continue == True:
		#		response['negState'] = NegState('accept-incomplete')
		#	else:
		#		response['negState'] = NegState('accept-completed')
		
		response['responseToken'] = result
		return response, to_continue, None
		
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
	
	async def authenticate(self, token, *args, **kwargs):
		"""
		This function is called (multiple times) during negotiation phase of a protocol to determine hich auth mechanism to be used
		Token is a byte array that is an ASN1 NegotiationToken structure.
		"""
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

				self.negtypes_store = MechTypes(mechtypes).dump()
					
					
				if len(mechtypes) == 1:
					self.selected_authentication_context_name = selected_name
					self.selected_authentication_context = self.authentication_contexts[selected_name]
					self.selected_mechtype = selected_name
					result, to_continue, err = await self.selected_authentication_context.authenticate(None, *args, **kwargs)
					if err is not None:
						return None, None, err

					if not result:
						return None, False, None
					if str(response['mechTypes'][0]) == '1.2.840.48018.1.2.2':
						response['mechToken'] = KRB5Token(result).to_bytes()
					else:
						response['mechToken'] = result
					
				### First message and ONLY the first message goes out with additional wrapping
				negtoken = NegotiationToken({'negTokenInit':NegTokenInit2(response)})
				return GSSAPI({'type': GSSType('1.3.6.1.5.5.2'), 'value':negtoken}).dump(), True, None
					
					
			else:
				#we have already send the NegTokenInit2, but it contained multiple auth types,
				#at this point server is replying which auth type to use
				neg_token_raw = NegotiationToken.load(token)
				neg_token = neg_token_raw.native
				
				if not isinstance(neg_token_raw, NegTokenResp):
					raise Exception('Server sent init???')
					
				self.selected_authentication_context_name = neg_token.mechTypes[0]
				self.selected_authentication_context = self.authentication_contexts[neg_token.mechTypes[0]]
				self.selected_mechtype = neg_token['supportedMech']
	
				response, to_continue, err = await self.process_ctx_authenticate(neg_token['responseToken'], *args, **kwargs)
				if err is not None:
					return None, None, err
				return NegTokenResp(response).dump(), to_continue, None
					
		else:
			#everything is netotiated, but authentication needs more setps
			neg_token_raw = NegotiationToken.load(token)
			neg_token = neg_token_raw.native
			if neg_token['negState'] == 'accept-completed' and neg_token['responseToken'] is None:
				return None, False, None
			if neg_token['responseToken'] is None:
				# https://tools.ietf.org/html/rfc4178#section-5
				# mechlistmic exchange happening at the end of the authentication
				return None, True, None
				#raise Exception('Should not be here....')
				#print('server mechListMIC: %s' % neg_token['mechListMIC'])
				#res = await self.verify(self.negtypes_store, neg_token['mechListMIC'])
				#print('res %s' % res)
				#print(self.negtypes_store)
				#print(self.negtypes_store.hex())
				#ret = await self.sign(self.negtypes_store, 0)
				#print(ret)
				#print(ret.hex())
				#res = {
				#	'mechListMIC' : ret, 
				#	'negState': NegState('accept-completed')
				#}
				#return NegotiationToken({'negTokenResp':NegTokenResp(res)}).dump(), True, None

			else:
				response, to_continue, err = await self.process_ctx_authenticate(neg_token['responseToken'], *args, **kwargs)
				if err is not None:
					return None, None, err
				if not response:
					return None, False, None

				if self.selected_mechtype.startswith('NTLM'):
					response['mechListMIC'] = await self.sign(self.negtypes_store, 0, reset_cipher = True)
					self.internal_seq += 1
				res = NegotiationToken({'negTokenResp':NegTokenResp(response)}).dump()

				if neg_token['negState'] == 'accept-completed':
					return None, False, None
				return res, to_continue, None
	
def test():
	test_data = bytes.fromhex('a03e303ca00e300c060a2b06010401823702020aa22a04284e544c4d5353500001000000978208e2000000000000000000000000000000000a00d73a0000000f')
	neg_token = NegotiationToken.load(test_data)
	print(neg_token.native)


	test_data_2 = bytes.fromhex('a181ce3081cba0030a0101a10c060a2b06010401823702020aa281b50481b24e544c4d53535000020000000800080038000000158289e2a7314a557bdb11bf000000000000000072007200400000000a0063450000000f540045005300540002000800540045005300540001001200570049004e003200300031003900410044000400120074006500730074002e0063006f007200700003002600570049004e003200300031003900410044002e0074006500730074002e0063006f007200700007000800aec600bfc5fdd40100000000')
	neg_token = NegotiationToken.load(test_data_2)
	print(neg_token.native)

	test_data_3 = bytes.fromhex('a11b3019a0030a0100a3120410010000006b65125a00bb9ab400000000')
	neg_token = NegotiationToken.load(test_data_3)
	print(neg_token.native)

	mt = MechType('NTLMSSP - Microsoft NTLM Security Support Provider')
	print(mt)

	print(MechType.map('1.3.6.1.4.1.311.2.2.10'))
	print(MechType.unmap('1.3.6.1.4.1.311.2.2.10'))

	#spnego_test = SPNEGO()
	#spnego_test.authenticate(test_data_2)
if __name__ == '__main__':
	test()