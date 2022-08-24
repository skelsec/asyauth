
import enum
from asyauth.common.winapi.constants import SECPKG_ATTR, SECPKG_CRED, ISC_REQ, SEC_E, SSPIResult
from asyauth.common.winapi.functiondefs import AcquireCredentialsHandle, InitializeSecurityContext, DecryptMessage, EncryptMessage, SecPkgContext_SessionKey, QueryContextAttributes

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
		
	def get_session_key(self):
		sec_struct = SecPkgContext_SessionKey()
		QueryContextAttributes(self.context, SECPKG_ATTR.SESSION_KEY, sec_struct)
		return sec_struct.Buffer
		
	def acquire_handle(self, client_name, target_name, flags = SECPKG_CRED.BOTH):
		self.cred_struct = AcquireCredentialsHandle(client_name, self.package.value, target_name, flags)
		
	def initialize_context(self, target, token_data = None, flags = ISC_REQ.INTEGRITY | ISC_REQ.CONFIDENTIALITY | ISC_REQ.SEQUENCE_DETECT | ISC_REQ.REPLAY_DETECT):
		res, self.context, data, self.flags, expiry = InitializeSecurityContext(self.cred_struct, target, token = token_data, ctx = self.context, flags = flags)
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