import io
import enum

from asyauth.protocols.spnego.messages.asn1_structs import KRB5Token
from minikerberos.gssapi.gssapi import get_gssapi, GSSWrapToken
from minikerberos.protocol.asn1_structs import AP_REQ, AP_REP, TGS_REP
from minikerberos.protocol.encryption import Enctype, Key, _enctype_table
from wsnet.operator.sspiproxy import WSNETSSPIProxy
from asn1crypto.core import ObjectIdentifier
from asyauth.common.winapi.constants import ISC_REQ

class KRB5_MECH_INDEP_TOKEN:
	# https://tools.ietf.org/html/rfc2743#page-81
	# Mechanism-Independent Token Format

	def __init__(self, data, oid, remlen = None):
		self.oid = oid
		self.data = data

		#dont set this
		self.length = remlen
	
	@staticmethod
	def from_bytes(data):
		return KRB5_MECH_INDEP_TOKEN.from_buffer(io.BytesIO(data))
	
	@staticmethod
	def from_buffer(buff):
		
		start = buff.read(1)
		if start != b'\x60':
			raise Exception('Incorrect token data!')
		remaining_length = KRB5_MECH_INDEP_TOKEN.decode_length_buffer(buff)
		token_data = buff.read(remaining_length)
		
		buff = io.BytesIO(token_data)
		pos = buff.tell()
		buff.read(1)
		oid_length = KRB5_MECH_INDEP_TOKEN.decode_length_buffer(buff)
		buff.seek(pos)
		token_oid = ObjectIdentifier.load(buff.read(oid_length+2))
		
		return KRB5_MECH_INDEP_TOKEN(buff.read(), str(token_oid), remlen = remaining_length)
		
	@staticmethod
	def decode_length_buffer(buff):
		lf = buff.read(1)[0]
		if lf <= 127:
			length = lf
		else:
			bcount = lf - 128
			length = int.from_bytes(buff.read(bcount), byteorder = 'big', signed = False)
		return length
		
	@staticmethod
	def encode_length(length):
		if length <= 127:
			return length.to_bytes(1, byteorder = 'big', signed = False)
		else:
			lb = length.to_bytes((length.bit_length() + 7) // 8, 'big')
			return (128+len(lb)).to_bytes(1, byteorder = 'big', signed = False) + lb
		
		
	def to_bytes(self):
		t = ObjectIdentifier(self.oid).dump() + self.data
		t = b'\x60' + KRB5_MECH_INDEP_TOKEN.encode_length(len(t)) + t
		return t[:-len(self.data)] , self.data

class KerberosClientSSPIProxy:
	def __init__(self, credential):
		self.iterations = 0
		self.credential = credential
		self.ksspi = WSNETSSPIProxy(credential.subprotocol.get_url(), credential.subprotocol.agentid)
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
	
	async def authenticate(self, authData = None, flags = ISC_REQ.CONNECTION, seq_number = 0, is_rpc = False, **kwargs):
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
		