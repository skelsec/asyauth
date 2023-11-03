
from minikerberos.gssapi.gssapi import get_gssapi, GSSWrapToken
from minikerberos.protocol.asn1_structs import AP_REP
from minikerberos.protocol.encryption import Key
from wsnet.clientauth import WSNETAuth
from asyauth.common.winapi.constants import ISC_REQ



class KerberosClientWSNET:
	def __init__(self, settings):
		self.iterations = 0
		self.settings = settings
		self.ksspi = WSNETAuth()
		self.client = None
		self.target = None
		self.gssapi = None
		self.etype = None
		self.session_key = None
		self.seq_number = None
		
		self.setup()
		
	def setup(self):
		return

	def get_seq_number(self):
		return self.seq_number
		
	async def encrypt(self, data, message_no):
		return self.gssapi.GSS_Wrap(data, message_no)
		
	async def decrypt(self, data, message_no, direction='init', auth_data=None):
		return self.gssapi.GSS_Unwrap(data, message_no, direction=direction, auth_data=auth_data)
	
	def get_session_key(self):
		return self.session_key
	
	async def authenticate(self, authData = None, flags = ISC_REQ.CONNECTION, seq_number = 0, is_rpc = False):
		try:
			if is_rpc == True:
				if self.iterations == 0:
					flags = ISC_REQ.CONFIDENTIALITY | \
							ISC_REQ.INTEGRITY | \
							ISC_REQ.MUTUAL_AUTH | \
							ISC_REQ.REPLAY_DETECT | \
							ISC_REQ.SEQUENCE_DETECT|\
							ISC_REQ.USE_DCE_STYLE
					
					
					status, ctxattr, apreq, err = await self.ksspi.authenticate('KERBEROS', '', 'termsrv/%s' % self.settings.target, 3, flags.value, authdata = b'')
					if err is not None:
						raise err
					self.iterations += 1
					return apreq, True, None
				
				elif self.iterations == 1:
					status, ctxattr, data, err = await self.ksspi.authenticate('KERBEROS', '','termsrv/%s' % self.settings.target, 3, flags.value, authdata = authData)
					if err is not None:
						return None, None, err
					self.session_key, err = await self.ksspi.get_sessionkey()
					if err is not None:
						return None, None, err
						
					aprep = AP_REP.load(data).native
					subkey = Key(aprep['enc-part']['etype'], self.session_key)
					self.gssapi = get_gssapi(subkey)

					if aprep['enc-part']['etype'] != 23: #no need for seq number in rc4
						raw_seq_data, err = await self.ksspi.get_sequenceno()
						if err is not None:
							return None, None, err
						self.seq_number = GSSWrapToken.from_bytes(raw_seq_data[16:]).SND_SEQ
					
					self.iterations += 1
					await self.ksspi.disconnect()
					return data, False, None
					
				else:
					raise Exception('SSPI Kerberos -RPC - auth encountered too many calls for authenticate.')
			
				
			else:
				status, ctxattr, apreq, err = await self.ksspi.authenticate('KERBEROS', '','termsrv/%s' % self.settings.target, 3, flags.value, authdata = b'')
				if err is not None:
					return None, None, err
				
				self.session_key, err = await self.ksspi.get_sessionkey()
				if err is not None:
					raise err
				await self.ksspi.disconnect()

				return apreq, False, None
		except Exception as e:
			return None, None, e
		