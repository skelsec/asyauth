import os
from asyauth import logger
from asyauth.protocols.kerberos.gssapi import get_gssapi
from asyauth.protocols.kerberos.gssapismb import get_gssapi as gssapi_smb
from asyauth.common.winapi.token import InitialContextToken
from asyauth.common.winapi.constants import ISC_REQ

from minikerberos.protocol.encryption import Key, _enctype_table
from minikerberos.protocol.asn1_structs import AP_REP, AP_REQ
from minikerberos.protocol.encryption import Key
from minikerberos.gssapi.gssapi import GSSWrapToken
from wsnet.agent.direct.auth import WSNETDirectAuth


class KerberosClientWSNETDirect:
	def __init__(self, credential):
		self._authid = os.urandom(4).hex()
		self.credential = credential
		self.iterations = 0
		self.ksspi = None
		self.client = None
		self.target = None
		self.gssapi = None
		self.etype = None
		self.session_key = None
		self.seq_number = None
		self.flags = None

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
		return ISC_REQ.INTEGRITY in self.flags
	
	def encryption_needed(self):
		"""
		Checks if confidentiality flag was negotiated
		"""
		return ISC_REQ.CONFIDENTIALITY in self.flags
				
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
	
	async def authenticate(self, authData, flags:ISC_REQ = None, cb_data = None, spn=None):
		logger.debug('[WSNETDirect][Kerberos][%s] spn: %s' % (self._authid, spn))
		logger.debug('[WSNETDirect][Kerberos][%s] flags: %s' % (self._authid, flags))
		logger.debug('[WSNETDirect][Kerberos][%s] cb_data: %s' % (self._authid, cb_data))
		logger.debug('[WSNETDirect][Kerberos][%s] authData: %s' % (self._authid, authData))
		
		try:
			if self.ksspi is None:
				self.ksspi = WSNETDirectAuth(self.credential.subprotocol.get_url())
				_, err = await self.ksspi.connect()
				if err is not None:
					raise err
			
			if flags is None:
				flags = ISC_REQ.CONFIDENTIALITY | \
							ISC_REQ.INTEGRITY | \
							ISC_REQ.REPLAY_DETECT | \
							ISC_REQ.SEQUENCE_DETECT #| \
							#ISC_REQ.MUTUAL_AUTH 
							
			
			if ISC_REQ.MUTUAL_AUTH in flags:
				
				if self.iterations == 0:
					flags = ISC_REQ.CONFIDENTIALITY | \
							ISC_REQ.INTEGRITY | \
							ISC_REQ.MUTUAL_AUTH | \
							ISC_REQ.REPLAY_DETECT | \
							ISC_REQ.SEQUENCE_DETECT|\
							ISC_REQ.USE_DCE_STYLE
					
					logger.debug('[WSNETDirect][Kerberos][%s] Initializing auth context, fetching ticket' % self._authid)
					status, retflags, apreq, err = await self.ksspi.authenticate('KERBEROS', '', spn, 3, flags.value, authdata = b'')
					logger.debug('[WSNETDirect][Kerberos][%s][Response] Status: %s' % (self._authid, status))
					logger.debug('[WSNETDirect][Kerberos][%s][Response] Response flags: %s' % (self._authid, retflags))
					logger.debug('[WSNETDirect][Kerberos][%s][Response] APREQ: %s' % (self._authid, apreq))
					if err is not None:
						raise err
					self.flags = ISC_REQ(retflags)
					self.iterations += 1
					return apreq, True, None
				
				elif self.iterations == 1:
					logger.debug('[WSNETDirect][Kerberos][%s] Calling remote end for mutual auth...' % self._authid)
					status, retflags, data, err = await self.ksspi.authenticate('KERBEROS', '', spn, 3, flags.value, authdata = authData)
					logger.debug('[WSNETDirect][Kerberos][%s][Response] Status: %s' % (self._authid, status))
					logger.debug('[WSNETDirect][Kerberos][%s][Response] Response flags: %s' % (self._authid, retflags))
					logger.debug('[WSNETDirect][Kerberos][%s][Response] Response data: %s' % (self._authid, data))
					if err is not None:
						return None, None, err
					self.flags = ISC_REQ(retflags)
					logger.debug('[WSNETDirect][Kerberos][%s] Calling remote end to fetch Session Key...' % (self._authid))
					session_key_data, err = await self.ksspi.get_sessionkey()
					if err is not None:
						return None, None, err
					logger.debug('[WSNETDirect][Kerberos][%s][Response] SessionKey: %s' % (self._authid, session_key_data.hex()))
						
					aprep = AP_REP.load(data).native
					self.session_key = Key(aprep['enc-part']['etype'], session_key_data)

					if ISC_REQ.USE_DCE_STYLE in self.flags:
						self.gssapi = gssapi_smb(self.session_key)
					else:
						self.gssapi = get_gssapi(self.session_key)

					#self.gssapi = get_gssapi(self.session_key)

					if aprep['enc-part']['etype'] != 23: #no need for seq number in rc4
						logger.debug('[WSNETDirect][Kerberos][%s] Calling remote end to fetch SequenceNo' % (self._authid))
						raw_seq_data, err = await self.ksspi.get_sequenceno()
						if err is not None:
							return None, None, err
						logger.debug('[WSNETDirect][Kerberos][%s][Response] Got wrapped token with SequenceNo, parsing...' % (self._authid))
						self.seq_number = GSSWrapToken.from_bytes(raw_seq_data[16:]).SND_SEQ
						logger.debug('[WSNETDirect][Kerberos][%s][Response] Got SequenceNo: %s' % (self._authid, self.seq_number))
					
					self.iterations += 1
					await self.ksspi.disconnect()
					return data, False, None
					
				else:
					raise Exception('SSPI Kerberos -RPC - auth encountered too many calls for authenticate.')
			
				
			else:
				logger.debug('[WSNETDirect][Kerberos][%s] Initializing auth context, fetching ticket' % self._authid)
				status, retflags, tokendata, err = await self.ksspi.authenticate('KERBEROS', '', spn, 3, flags.value, authdata = b'')
				if err is not None:
					return None, None, err
				self.flags = ISC_REQ(retflags)
				logger.debug('[WSNETDirect][Kerberos][%s][Response] Status: %s' % (self._authid, status))
				logger.debug('[WSNETDirect][Kerberos][%s][Response] Response flags: %s' % (self._authid, self.flags))
				logger.debug('[WSNETDirect][Kerberos][%s][Response] Response contexttoken: %s' % (self._authid, tokendata.hex()))

				token = InitialContextToken.load(tokendata)
				apreq = AP_REQ(token.native['innerContextToken'])
				
				logger.debug('[WSNETDirect][Kerberos][%s] Calling remote end to fetch Session Key...' % (self._authid))
				session_key_data, err = await self.ksspi.get_sessionkey()
				if err is not None:
					raise err
				
				cipher = _enctype_table[int(apreq.native['ticket']['enc-part']['etype'])]()
				self.session_key = Key(cipher.enctype, session_key_data)
				logger.debug('[WSNETDirect][Kerberos][%s][Response] SessionKey: %s' % (self._authid, session_key_data.hex()))
				await self.ksspi.disconnect()

				if apreq.native['ticket']['enc-part']['etype'] != 23: #no need for seq number in rc4
					logger.debug('[WSNETDirect][Kerberos][%s] Calling remote end to fetch SequenceNo' % (self._authid))
					raw_seq_data, err = await self.ksspi.get_sequenceno()
					if err is not None:
						return None, None, err
					logger.debug('[WSNETDirect][Kerberos][%s][Response] Got wrapped token with SequenceNo, parsing...' % (self._authid))
					self.seq_number = GSSWrapToken.from_bytes(raw_seq_data[16:]).SND_SEQ
					logger.debug('[WSNETDirect][Kerberos][%s][Response] Got SequenceNo: %s' % (self._authid, self.seq_number))

				if ISC_REQ.USE_DCE_STYLE in self.flags:
					self.gssapi = gssapi_smb(self.session_key)
				else:
					self.gssapi = get_gssapi(self.session_key)

				return apreq.dump(), False, None
		except Exception as e:
			return None, None, e
		