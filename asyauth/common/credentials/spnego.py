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
				if credential.protocol == asyauthProtocol.KERBEROS:
					context = credential.build_context(**kwargs)
					sspi_ctx.add_auth_context('MS KRB5 - Microsoft Kerberos 5', context)
				elif credential.protocol == asyauthProtocol.NTLM:
					context = credential.build_context(**kwargs)
					sspi_ctx.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', context)
				elif credential.protocol in (
					asyauthProtocol.PLAIN,
					asyauthProtocol.NONE,
					asyauthProtocol.CREDSSP,
					asyauthProtocol.SPNEGO,
					asyauthProtocol.SPNEGOEX,
				):
					# No concrete inner mechanism was specified. This happens when
					# a developer creates a plain credential (or one mistakenly
					# tagged with a wrapper protocol) and adds it to the SPNEGO
					# credential. It's not possible to tell what the protocol is, so
					# we default to NTLM.
					from asyauth import logger
					logger.warning(
						'SPNEGO: no concrete inner authentication protocol for credential '
						'(protocol=%s); defaulting to NTLM.',
						credential.protocol.name if credential.protocol is not None else credential.protocol,
					)
					context = credential.build_context(asyauthProtocol.NTLM)
					sspi_ctx.add_auth_context('NTLMSSP - Microsoft NTLM Security Support Provider', context)
				else:
					raise Exception('Authentication protocol "%s" is not supported for SPNEGO' % credential.protocol)
			return sspi_ctx

		else:
			raise Exception('Unsupported subprotocol "%s"' % self.subprotocol)