from asyauth.protocols.ntlm.structures.fields import Fields
from asyauth.protocols.ntlm.structures.negotiate_flags import NegotiateFlags
from asyauth.protocols.ntlm.structures.version import Version
from asyauth.protocols.ntlm.structures.avpair import AVPairs, AVPAIRType

NTLMServerTemplates = {
		"Windows2003_nosig" : {
			'flags'      :  NegotiateFlags.NEGOTIATE_56|NegotiateFlags.NEGOTIATE_128|
							NegotiateFlags.NEGOTIATE_VERSION|NegotiateFlags.NEGOTIATE_TARGET_INFO|
							NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY|
							NegotiateFlags.TARGET_TYPE_DOMAIN|NegotiateFlags.NEGOTIATE_NTLM|
							NegotiateFlags.REQUEST_TARGET|NegotiateFlags.NEGOTIATE_UNICODE ,
			'version'    : Version.from_bytes(b"\x05\x02\xce\x0e\x00\x00\x00\x0f"),
			'targetinfo' : AVPairs({ AVPAIRType.MsvAvNbDomainName    : 'RDP',
								AVPAIRType.MsvAvNbComputerName       : 'RDP-TOOLKIT',
								AVPAIRType.MsvAvDnsDomainName        : 'RDP.local',
								AVPAIRType.MsvAvDnsComputerName      : 'server2003.RDP.local',
								AVPAIRType.MsvAvDnsTreeName          : 'RDP.local',
						   }),

			'targetname' : 'RDP',
		},
		"Windows2003" : {
			'flags'      :  NegotiateFlags.NEGOTIATE_56|NegotiateFlags.NEGOTIATE_128|
							NegotiateFlags.NEGOTIATE_KEY_EXCH|NegotiateFlags.NEGOTIATE_ALWAYS_SIGN|NegotiateFlags.NEGOTIATE_SIGN|
							NegotiateFlags.NEGOTIATE_VERSION|NegotiateFlags.NEGOTIATE_TARGET_INFO|
							NegotiateFlags.NEGOTIATE_EXTENDED_SESSIONSECURITY|
							NegotiateFlags.TARGET_TYPE_DOMAIN|NegotiateFlags.NEGOTIATE_NTLM|
							NegotiateFlags.REQUEST_TARGET|NegotiateFlags.NEGOTIATE_UNICODE,
			'version'    : Version.from_bytes(b"\x05\x02\xce\x0e\x00\x00\x00\x0f"),
			'targetinfo' : AVPairs({ AVPAIRType.MsvAvNbDomainName    : 'RDP',
								AVPAIRType.MsvAvNbComputerName       : 'RDP-TOOLKIT',
								AVPAIRType.MsvAvDnsDomainName        : 'RDP.local',
								AVPAIRType.MsvAvDnsComputerName      : 'server2003.RDP.local',
								AVPAIRType.MsvAvDnsTreeName          : 'RDP.local',
						   }),

			'targetname' : 'RDP',
		},
}