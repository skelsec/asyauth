
import enum
from asyauth.common.winapi.constants import SECPKG_ATTR, SECPKG_CRED, ISC_REQ, SEC_E, SSPIResult
from asyauth.common.winapi.functiondefs import AcquireCredentialsHandle, InitializeSecurityContext,\
	DecryptMessage, EncryptMessage, SecPkgContext_SessionKey, QueryContextAttributes,\
	GetSequenceNumberFromEncryptdataKerberos
from minikerberos.protocol.asn1_structs import AP_REQ
from asyauth.common.winapi.token import InitialContextToken

class SSPIPackage(enum.Enum):
	NTLM = 'NTLM'
	KERBEROS = 'KERBEROS'
	DIGEST = 'DIGEST'
	NEGOTIATE = 'NEGOTIATE'
	CREDSSP = 'CREDSSP'
	SCHANNEL = 'SCHANNEL'

# first you must call initialize!
class WinSSPI:
	def __init__(self, package:SSPIPackage):
		self.cred_struct = None
		self.context = None
		self.package = package
		self.flags = None

	def get_seq_number(self):
		#only call it once!
		return GetSequenceNumberFromEncryptdataKerberos(self.context)
		
	def get_session_key(self):
		sec_struct = SecPkgContext_SessionKey()
		QueryContextAttributes(self.context, SECPKG_ATTR.SESSION_KEY, sec_struct)
		return sec_struct.Buffer
		
	def acquire_handle(self, client_name, target_name, flags = SECPKG_CRED.BOTH):
		self.cred_struct = AcquireCredentialsHandle(client_name, self.package.value, target_name, flags)
		
	def initialize_context(self, target, token_data = None, flags = ISC_REQ.INTEGRITY | ISC_REQ.CONFIDENTIALITY | ISC_REQ.SEQUENCE_DETECT | ISC_REQ.REPLAY_DETECT, cb_data = None):
		res, self.context, data, self.flags, expiry = InitializeSecurityContext(self.cred_struct, target, token = token_data, ctx = self.context, flags = flags, cb_data=cb_data)
		if res == SEC_E.OK:
			return SSPIResult.OK, data, self.flags, expiry
		else:
			return SSPIResult.CONTINUE, data, self.flags, expiry
			
	def _unwrap(self, data, message_no = 0):
		data_buff = DecryptMessage(self.context, data, message_no)
		return data_buff
		
	def _wrap(self, data, message_no = 0):
		data_buff = EncryptMessage(self.context, data, message_no)
		return data_buff

	def get_ticket_for_spn(self, target_name, flags = None, token_data = None, client_name = None, cb_data = None):
		try:
			self.target_name = target_name
			if not self.cred_struct:
				self.acquire_handle(client_name, self.target_name)
			
			if ISC_REQ.USE_DCE_STYLE in flags:
				res, self.context, data, outputflags, expiry = InitializeSecurityContext(self.cred_struct, self.target_name, token = token_data, ctx = self.context, flags = flags, cb_data=cb_data)
				return data, outputflags, None
			else:
				res, self.context, data, outputflags, expiry = InitializeSecurityContext(self.cred_struct, self.target_name, token = None, ctx = self.context, flags = flags, cb_data=cb_data)
				token = InitialContextToken.load(data) #this is disgusting :(
				return AP_REQ(token.native['innerContextToken']).dump(), outputflags, None #this is the AP_REQ
		except Exception as e:
			return None, None, e