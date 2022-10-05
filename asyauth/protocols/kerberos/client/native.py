
from asyauth import logger
from asyauth.common.winapi.constants import ISC_REQ
from asyauth.protocols.kerberos.gssapi import get_gssapi
from asyauth.protocols.kerberos.gssapismb import get_gssapi as gssapi_smb
from minikerberos.protocol.asn1_structs import AP_REP, EncAPRepPart, Ticket
from minikerberos.protocol.structures import ChecksumFlags
from minikerberos.gssapi.gssapi import GSSAPIFlags
from minikerberos.protocol.encryption import Key, _enctype_table
from minikerberos.aioclient import AIOKerberosClient
from asyauth.common.credentials.kerberos import KerberosCredential
from minikerberos.common.spn import KerberosSPN
import datetime
from minikerberos.protocol.constants import MESSAGE_TYPE
from minikerberos.protocol.asn1_structs import AP_REP, EncAPRepPart, EncryptedData, Ticket


class KerberosClientNative:
	def __init__(self, credential:KerberosCredential):
		self.credential = credential
		self.ccred = self.credential.to_ccred()
		
		self.kc = None
		self.session_key = None
		self.gssapi = None
		self.iterations = 0
		self.seq_number = 0
		self.from_ccache = False
	
		self.flags = \
			GSSAPIFlags.GSS_C_CONF_FLAG |\
			GSSAPIFlags.GSS_C_INTEG_FLAG |\
			GSSAPIFlags.GSS_C_REPLAY_FLAG |\
			GSSAPIFlags.GSS_C_SEQUENCE_FLAG
		
	
	def get_seq_number(self):
		"""
		Returns the initial sequence number. It is 0 by default, but can be adjusted during authentication, 
		by passing the 'seq_number' parameter in the 'authenticate' function
		"""
		return self.seq_number
	
	def signing_needed(self):
		"""
		Checks if integrity protection was negotiated
		"""
		return GSSAPIFlags.GSS_C_INTEG_FLAG in self.flags
	
	def encryption_needed(self):
		"""
		Checks if confidentiality flag was negotiated
		"""
		return GSSAPIFlags.GSS_C_CONF_FLAG in self.flags
				
	async def sign(self, data, message_no, direction = 'init'):
		"""
		Signs a message. 
		"""
		return self.gssapi.GSS_GetMIC(data, message_no, direction = direction)	
		
	async def encrypt(self, data, message_no, *args, **kwargs):
		"""
		Encrypts a message. 
		"""
		data, eeee  = self.gssapi.GSS_Wrap(data, message_no, *args, **kwargs)
		return data, eeee 
		
	async def decrypt(self, data, message_no, *args, **kwargs):
		"""
		Decrypts message. Also performs integrity checking.
		"""

		return self.gssapi.GSS_Unwrap(data, message_no, *args, **kwargs)
	
	def get_session_key(self):
		return self.session_key.contents

	def iscreq_to_gssapiflags(self, flags):
		if flags is None:
			return self.flags
		kflags = GSSAPIFlags.GSS_C_CONF_FLAG |\
			GSSAPIFlags.GSS_C_INTEG_FLAG |\
			GSSAPIFlags.GSS_C_REPLAY_FLAG |\
			GSSAPIFlags.GSS_C_SEQUENCE_FLAG
		if ISC_REQ.INTEGRITY in flags:
			kflags |= GSSAPIFlags.GSS_C_INTEG_FLAG
		else:
			kflags &= ~GSSAPIFlags.GSS_C_INTEG_FLAG
		if ISC_REQ.CONFIDENTIALITY in flags:
			kflags |= GSSAPIFlags.GSS_C_CONF_FLAG
		else:
			kflags &= ~GSSAPIFlags.GSS_C_CONF_FLAG
		if ISC_REQ.REPLAY_DETECT in flags:
			kflags |= GSSAPIFlags.GSS_C_REPLAY_FLAG
		else:
			kflags &= ~GSSAPIFlags.GSS_C_REPLAY_FLAG
		if ISC_REQ.SEQUENCE_DETECT in flags:
			kflags |= GSSAPIFlags.GSS_C_SEQUENCE_FLAG
		else:
			kflags &= ~GSSAPIFlags.GSS_C_SEQUENCE_FLAG
		if ISC_REQ.USE_DCE_STYLE in flags:
			kflags |= GSSAPIFlags.GSS_C_DCE_STYLE
		else:
			kflags &= ~GSSAPIFlags.GSS_C_DCE_STYLE
		if ISC_REQ.MUTUAL_AUTH in flags:
			kflags |= GSSAPIFlags.GSS_C_MUTUAL_FLAG
		else:
			kflags &= ~GSSAPIFlags.GSS_C_MUTUAL_FLAG
		return kflags
		
	
	async def authenticate(self, authData, flags = None, seq_number = 0, cb_data = None, spn = None):
		"""
		This function is called (multiple times depending on the flags) to perform authentication. 
		"""
		try:
			self.flags = self.iscreq_to_gssapiflags(flags)

			if spn is None:
				raise Exception("SPN is needed for kerberos!")
			else:
				spn = KerberosSPN.from_target_string(spn)

			if self.kc is None:
				self.kc = AIOKerberosClient(self.ccred, self.credential.target)

			if self.iterations == 0:
				self.seq_number = 0
				self.iterations += 1
				
				try:
					#check TGS first, maybe ccache already has what we need
					for target in self.ccred.ccache.list_targets():
						# just printing this to debug...
						logger.debug('CCACHE SPN record: %s' % target)
					tgs, encpart, self.session_key = await self.kc.get_TGS(spn)
					
					self.from_ccache = True
				except:
					tgt = await self.kc.get_TGT(override_etype = self.credential.etypes)
					tgs, encpart, self.session_key = await self.kc.get_TGS(spn)#, override_etype = self.preferred_etypes)
				
				ap_opts = []
				if GSSAPIFlags.GSS_C_MUTUAL_FLAG in self.flags or GSSAPIFlags.GSS_C_DCE_STYLE in self.flags:
					if GSSAPIFlags.GSS_C_MUTUAL_FLAG in self.flags:
						ap_opts.append('mutual-required')
					if self.from_ccache is False:
						apreq = self.kc.construct_apreq(
							tgs, 
							encpart, 
							self.session_key, 
							flags = self.flags, 
							seq_number = self.seq_number, 
							ap_opts=ap_opts, 
							cb_data = cb_data
						)
					else:
						apreq = self.kc.construct_apreq_from_ticket(
							Ticket(tgs['ticket']).dump(), 
							self.session_key, 
							tgs['crealm'], tgs['cname']['name-string'][0], 
							flags = self.flags, 
							seq_number = self.seq_number, 
							ap_opts = ap_opts, 
							cb_data = cb_data
						)
					return apreq, True, None
				
				else:
					#not mutual nor dce auth will take one step only
					if self.from_ccache is False:
						apreq = self.kc.construct_apreq(
							tgs, 
							encpart, 
							self.session_key, 
							flags = self.flags, 
							seq_number = self.seq_number, 
							ap_opts=ap_opts, 
							cb_data = cb_data)
					else:
						apreq = self.kc.construct_apreq_from_ticket(
							Ticket(tgs['ticket']).dump(), 
							self.session_key, 
							tgs['crealm'], 
							tgs['cname']['name-string'][0], 
							flags = self.flags, 
							seq_number = self.seq_number, 
							ap_opts = ap_opts, 
							cb_data = cb_data
						)
					
					
					self.gssapi = get_gssapi(self.session_key)
					return apreq, False, None

			else:
				self.seq_number = seq_number

				aprep = AP_REP.load(authData).native
				cipher = _enctype_table[int(aprep['enc-part']['etype'])]()
				cipher_text = aprep['enc-part']['cipher']
				temp = cipher.decrypt(self.session_key, 12, cipher_text)
					
				enc_part = EncAPRepPart.load(temp).native
				cipher = _enctype_table[int(enc_part['subkey']['keytype'])]()
					
				now = datetime.datetime.now(datetime.timezone.utc)
				apreppart_data = {}
				apreppart_data['cusec'] = now.microsecond
				apreppart_data['ctime'] = now.replace(microsecond=0)
				apreppart_data['seq-number'] = enc_part['seq-number']
				#print('seq %s' % enc_part['seq-number'])
				#self.seq_number = 0 #enc_part['seq-number']
					
				apreppart_data_enc = cipher.encrypt(self.session_key, 12, EncAPRepPart(apreppart_data).dump(), None)
					
				#overriding current session key
				self.session_key = Key(cipher.enctype, enc_part['subkey']['keyvalue'])
					
				ap_rep = {}
				ap_rep['pvno'] = 5 
				ap_rep['msg-type'] = MESSAGE_TYPE.KRB_AP_REP.value
				ap_rep['enc-part'] = EncryptedData({'etype': self.session_key.enctype, 'cipher': apreppart_data_enc}) 
					
				token = AP_REP(ap_rep).dump()
				if GSSAPIFlags.GSS_C_DCE_STYLE in self.flags:
					self.gssapi = gssapi_smb(self.session_key)
				else:
					self.gssapi = get_gssapi(self.session_key)
				self.iterations += 1
				return token, True, None
		
		except Exception as e:
			return None, None, e