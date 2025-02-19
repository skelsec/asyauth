from typing import List
from asyauth.common.credentials import UniCredential
from asyauth.common.constants import asyauthSecret, asyauthProtocol, asyauthSubProtocol
from asyauth.common.subprotocols import SubProtocol
from asyauth.common.subprotocols import SubProtocolNative

class SPNEGOCredential(UniCredential):
	def __init__(self, credentials:List[UniCredential] = [], subprotocol:SubProtocol = SubProtocolNative()):
		UniCredential.__init__(self, protocol = asyauthProtocol.SPNEGO, subprotocol=subprotocol)
		self.credentials = credentials
	
	def build_context(self, *args, **kwargs):
		if self.subprotocol.type == asyauthSubProtocol.NATIVE:
			from asyauth.protocols.spnego.client.native import SPNEGOClientNative
			if len(self.credentials) == 1 and isinstance(self.credentials[0], SPNEGOClientNative):
				return self.credentials[0].get_copy()
			
			sspi_ctx = SPNEGOClientNative(self)
			for credential in self.credentials:
				context = credential.build_context(**kwargs)
				if credential.protocol == asyauthProtocol.PLAIN:
					# this happens when the developer creates a plain credential and adds it to the SPNEGO credential
					# it's not possible to tell what the protocol is, so we assume it's NTLM
					context = credential.build_context(asyauthProtocol.NTLM)
					sspi_ctx.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', context)

				elif credential.protocol == asyauthProtocol.KERBEROS:
					sspi_ctx.add_auth_context('MS KRB5 - Microsoft Kerberos 5', context)
				elif credential.protocol == asyauthProtocol.NTLM:
					sspi_ctx.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', context)
				else:
					raise Exception('Authentication protocol "%s" is not supported for SPNEGO' % credential.protocol)
			return sspi_ctx

		else:
			raise Exception('Unsupported subprotocol "%s"' % self.subprotocol)