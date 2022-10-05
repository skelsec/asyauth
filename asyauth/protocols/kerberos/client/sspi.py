from minikerberos.protocol.asn1_structs import AP_REQ, AP_REP
from minikerberos.protocol.encryption import Enctype, Key, _enctype_table
from asyauth.common.winapi.winsspi import WinSSPI, SSPIPackage
from asyauth.common.winapi.constants import ISC_REQ
from asyauth.protocols.kerberos.gssapi import get_gssapi
from asyauth.protocols.kerberos.gssapismb import get_gssapi as gssapi_smb


class KerberosClientSSPI:
	def __init__(self, credential):
		self.iterations = 0
		self.credential = credential
		self.ksspi = WinSSPI(SSPIPackage.KERBEROS)
		self.gssapi = None
		self.etype = None
		self.actual_ctx_flags = None

		self.seq_number = None
		self.session_key = None

	def get_seq_number(self):
		"""
		Fetches the starting sequence number. This is either zero or can be found in the authenticator field of the 
		AP_REQ structure. As windows uses a random seq number AND a subkey as well, we can't obtain it by decrypting the 
		AP_REQ structure. Insead under the hood we perform an encryption operation via EncryptMessage API which will 
		yield the start sequence number
		"""
		if self.seq_number is None:
			self.seq_number = self.ksspi.get_seq_number()
		return self.seq_number

	def signing_needed(self):
		return ISC_REQ.INTEGRITY in self.actual_ctx_flags
	
	def encryption_needed(self):
		return ISC_REQ.CONFIDENTIALITY in self.actual_ctx_flags
		
	async def encrypt(self, data, message_no):
		return self.gssapi.GSS_Wrap(data, message_no)
		
	async def decrypt(self, data, message_no, direction='init', auth_data=None):
		return self.gssapi.GSS_Unwrap(data, message_no, direction=direction, auth_data=auth_data)
	
	def get_session_key(self):
		if self.session_key is None:
			self.session_key = self.ksspi.get_session_key()
		return self.session_key
	
	async def authenticate(self, authData = None, flags = ISC_REQ.CONNECTION, seq_number = 0, client_name = None, spn=None, cb_data = None):
		try:
			#authdata is only for api compatibility reasons
			if ISC_REQ.USE_DCE_STYLE in flags or ISC_REQ.MUTUAL_AUTH in flags:
				if self.iterations == 0:
					flags = ISC_REQ.CONFIDENTIALITY | \
							ISC_REQ.INTEGRITY | \
							ISC_REQ.MUTUAL_AUTH | \
							ISC_REQ.REPLAY_DETECT | \
							ISC_REQ.SEQUENCE_DETECT|\
							ISC_REQ.USE_DCE_STYLE
							
					token, self.actual_ctx_flags, err = self.ksspi.get_ticket_for_spn(spn, flags = flags, token_data = authData, cb_data = cb_data, client_name=client_name)
					if err is not None:
						raise err
					#print(token.hex())
					self.iterations += 1
					return token, True, None
				
				elif self.iterations == 1:
					flags = ISC_REQ.USE_DCE_STYLE		
					token, self.actual_ctx_flags, err = self.ksspi.get_ticket_for_spn(spn, flags = flags, token_data = authData, cb_data = cb_data, client_name=client_name)
					if err is not None:
						raise err
					
					aprep = AP_REP.load(token).native
					subkey = Key(aprep['enc-part']['etype'], self.get_session_key())

					self.get_seq_number()
					
					self.gssapi = gssapi_smb(subkey)
					
					self.iterations += 1
					return token, False, None
					
				else:
					raise Exception('SSPI Kerberos -RPC - auth encountered too many calls for authenticate.')
				
			else:
				apreqraw, self.actual_ctx_flags, err = self.ksspi.get_ticket_for_spn(spn, flags = flags, cb_data = cb_data, client_name=client_name)
				if err is not None:
					raise err
				
				if self.encryption_needed() is True or self.signing_needed() is True:
					self.get_seq_number()
					apreq = AP_REQ.load(apreqraw)
					skey = Key(apreq.native['ticket']['enc-part']['etype'], self.get_session_key())

					self.gssapi = get_gssapi(skey)
				return apreqraw, False, None
		except Exception as e:
			return None, True, e