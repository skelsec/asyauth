
from asyauth.common.credentials import UniCredential
from asyauth.common.constants import asyauthSecret, asyauthProtocol, asyauthSubProtocol
from asyauth.common.subprotocols import SubProtocol
from asyauth.common.subprotocols import SubProtocolNative

from asyauth.protocols.ntlm.structures.version import Version, WindowsMajorVersion, WindowsMinorVersion
from asyauth.protocols.ntlm.structures.negotiate_flags import NegotiateFlags

ASYAUTH_NTLMCRED_SUPPORTED_STYPE = [
	asyauthSecret.PASSWORD,
	asyauthSecret.PASS,
	asyauthSecret.PW,
	asyauthSecret.PWHEX,
	asyauthSecret.NT,
	asyauthSecret.RC4
]
class NTLMCredential(UniCredential):
	def __init__(self, secret, username, domain, stype:asyauthSecret, subprotocol:SubProtocol = SubProtocolNative()):
		UniCredential.__init__(
			self, 
			secret = secret,
			username = username,
			domain = domain,
			stype = stype,
			protocol = asyauthProtocol.NTLM,
			subprotocol=subprotocol
		)

		if self.stype is asyauthSecret.RC4:
			self.stype = asyauthSecret.NT
		if isinstance(self.subprotocol, SubProtocolNative) and self.stype not in ASYAUTH_NTLMCRED_SUPPORTED_STYPE:
			raise Exception('Unsupported Secret Type for NTLM auth: %s' % self.stype)
		
		self.is_guest = False
		self.negotiate_workstation = None
		self.negotiate_domain = None
		self.ntlm_version = 2
		self.flags = NegotiateFlags.NEGOTIATE_KEY_EXCH|\
			NegotiateFlags.NEGOTIATE_128|\
			NegotiateFlags.NEGOTIATE_VERSION|\
			NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY|\
			NegotiateFlags.NEGOTIATE_ALWAYS_SIGN|\
			NegotiateFlags.NEGOTIATE_NTLM|\
			NegotiateFlags.NEGOTIATE_SIGN|\
			NegotiateFlags.NEGOTIATE_SEAL|\
			NegotiateFlags.REQUEST_TARGET|\
			NegotiateFlags.NEGOTIATE_UNICODE
			
		self.negotiate_version = Version.construct(
			WindowsMajorVersion.WINDOWS_MAJOR_VERSION_10, 
			minor = WindowsMinorVersion.WINDOWS_MINOR_VERSION_0, 
			build = 15063 
		)

		### these fields are for testing!
		self.challenge = None # none -> it will generate a random challenge for the context
		self.timestamp = None
		self.session_key = None
	
	@staticmethod
	def create_guest():
		return NTLMCredential(
			secret = None,
			username= 'Guest',
			domain = None,
			stype = asyauthSecret.PASSWORD,
			subprotocol = SubProtocolNative()
		)
			
	@staticmethod
	def get_url_params():
		return {

		}
	
	def build_context(self, *args, **kwargs):
		if self.subprotocol.type == asyauthSubProtocol.NATIVE:
			from asyauth.protocols.ntlm.client.native import NTLMClientNative
			return NTLMClientNative(self)

		elif self.subprotocol.type == asyauthSubProtocol.SSPI:
			from asyauth.protocols.ntlm.client.sspi import NTLMClientSSPI
			return NTLMClientSSPI(self)

		elif self.subprotocol.type == asyauthSubProtocol.SSPIPROXY:
			from asyauth.protocols.ntlm.client.sspiproxy import NTLMClientSSPIProxy
			return NTLMClientSSPIProxy(self)

		elif self.subprotocol.type == asyauthSubProtocol.WSNET:
			from asyauth.protocols.ntlm.client.wsnet import NTLMClientWSNET
			return NTLMClientWSNET(self)
		
		elif self.subprotocol.type == asyauthSubProtocol.WSNETDIRECT:
			from asyauth.protocols.ntlm.client.wsnetdirect import NTLMClientWSNETDirect
			return NTLMClientWSNETDirect(self)
		
		elif self.subprotocol.type == asyauthSubProtocol.CUSTOM:
			return self.subprotocol.factoryobj.build_context(self)
		else:
			raise Exception('Unsupported subprotocol "%s"' % self.subprotocol)
	
	def __str__(self):
		import enum
		t = '==== NTLMCredential ====\r\n'
		for k in self.__dict__:
			val = self.__dict__[k]
			if isinstance(val, enum.IntFlag):
				val = val
			elif isinstance(val, enum.Enum):
				val = val.name
			
			t += '%s: %s\r\n' % (k, str(val))
			
		return t