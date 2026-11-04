import io

from asyauth.protocols.ntlm.structures.fields import Fields
from asyauth.protocols.ntlm.structures.negotiate_flags import NegotiateFlags
from asyauth.protocols.ntlm.structures.version import Version
from asyauth.protocols.ntlm.structures.challenge_response import *
from asyauth.protocols.ntlm.structures.avpair import MsvAvFlags, AVPAIRType

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/033d32cc-88f9-4483-9bf2-b273055038ce
class NTLMAuthenticate:
	def __init__(self, _use_NTLMv2 = True):
		self.Signature = b'NTLMSSP\x00'
		self.MessageType = 3
		self.LmChallengeResponseFields = None
		self.NtChallengeResponseFields = None
		self.DomainNameFields = None
		self.UserNameFields = None
		self.WorkstationFields = None
		self.EncryptedRandomSessionKeyFields = None
		self.NegotiateFlags = None
		self.Version = None
		self.MIC = None
		self.Payload = None

		# high level
		self.LMChallenge = None
		self.NTChallenge = None
		self.DomainName = None
		self.UserName = None
		self.Workstation = None
		self.EncryptedRandomSession = None

		# this is a global variable that needs to be indicated
		self._use_NTLMv2 = _use_NTLMv2
		
	@staticmethod
	def construct(flags, domainname= None, workstationname= None, username= None, encrypted_session= None, lm_response= None, nt_response= None, version = None, mic = b'\x00'*16):
		auth = NTLMAuthenticate()
		auth.Payload = b''
		
		payload_pos = 8+4+8+8+8+8+8+8+4
		if flags & NegotiateFlags.NEGOTIATE_VERSION:
			if not version:
				raise Exception('NEGOTIATE_VERSION set but no Version supplied!')
				
			auth.Version = version
			
			payload_pos += 8
			
		if mic is not None:
			auth.MIC = mic
			payload_pos += 16
			
		if lm_response:
			data =  lm_response.to_bytes()
			auth.Payload += data
			auth.LmChallengeResponseFields  = Fields(len(data), payload_pos)
			payload_pos += len(data)
			auth.LMChallenge = lm_response
		else:
			auth.LmChallengeResponseFields  = Fields(0,0)
			
		if nt_response:
			data =  nt_response.to_bytes()
			auth.Payload += data
			auth.NtChallengeResponseFields  = Fields(len(data), payload_pos)
			payload_pos += len(data)
			auth.NTChallenge = nt_response
		else:
			auth.NtChallengeResponseFields  = Fields(0,payload_pos)
		
		
		if domainname:
			data =  domainname.encode('utf-16le')
			auth.Payload += data
			auth.DomainNameFields  = Fields(len(data), payload_pos)
			payload_pos += len(data)
			auth.DomainName = domainname
		else:
			auth.DomainNameFields  = Fields(0,payload_pos)
		
		if username:
			data =  username.encode('utf-16le')
			auth.Payload += data
			auth.UserNameFields  = Fields(len(data), payload_pos)
			payload_pos += len(data)
			auth.UserName = username
		else:
			auth.UserNameFields  = Fields(0,payload_pos)
		
		if workstationname:
			data =  workstationname.encode('utf-16le')
			auth.Payload += data
			auth.WorkstationFields  = Fields(len(data), payload_pos)
			payload_pos += len(data)
			auth.Workstation = workstationname
		else:
			auth.WorkstationFields  = Fields(0,payload_pos)
			
		if encrypted_session:
			data =  encrypted_session
			auth.Payload += data
			auth.EncryptedRandomSessionKeyFields  = Fields(len(data), payload_pos)
			payload_pos += len(data)
			auth.EncryptedRandomSession = encrypted_session
		else:
			auth.EncryptedRandomSessionKeyFields  = Fields(0,payload_pos)
				
		auth.NegotiateFlags = flags
		return auth
		
	def to_bytes(self):
		t = b''
		t += self.Signature
		t += self.MessageType.to_bytes(4, byteorder = 'little', signed = False)

		t += self.LmChallengeResponseFields.to_bytes()
		t += self.NtChallengeResponseFields.to_bytes()
		t += self.DomainNameFields.to_bytes()
		t += self.UserNameFields.to_bytes()
		t += self.WorkstationFields.to_bytes()
		t += self.EncryptedRandomSessionKeyFields.to_bytes()
		t += self.NegotiateFlags.to_bytes(4, byteorder = 'little', signed = False)
		if self.Version is not None:
			if isinstance(self.Version, bytes):
				# parsing might have failed, fall back to raw bytes
				t += self.Version
			else:
				t += self.Version.to_bytes()

		if isinstance(self.NTChallenge, NTLMv2Response) and AVPAIRType.MsvAvFlags in self.NTChallenge.ChallengeFromClinet.Details:
			# only emit MIC if MIC_PRESENT is actually set (it may have been dropped by a relay)
			if self.MIC is not None and MsvAvFlags.MIC_PRESENT in self.NTChallenge.ChallengeFromClinet.Details[AVPAIRType.MsvAvFlags]:
				t += self.MIC

		t += self.Payload
		return t

	def to_bytes_full(self):
		"""
		Rebuild the message from the high-level fields, ignoring self.Payload.
		Use this after mutating fields whose serialized length may have changed
		(e.g. dropping MIC-related AVPairs from the NTv2 client challenge).
		"""
		payload = b''
		payload_pos = 8+4+8+8+8+8+8+8+4
		if self.Version is not None:
			payload_pos += 8

		if self.MIC is not None:
			payload_pos += 16

		if self.LMChallenge is not None:
			data = self.LMChallenge.to_bytes()
			self.LmChallengeResponseFields = Fields(len(data), payload_pos)
			payload += data
			payload_pos += len(data)
		else:
			self.LmChallengeResponseFields = Fields(0, payload_pos)

		if self.NTChallenge is not None:
			data = self.NTChallenge.to_bytes()
			self.NtChallengeResponseFields = Fields(len(data), payload_pos)
			payload += data
			payload_pos += len(data)
		else:
			self.NtChallengeResponseFields = Fields(0, payload_pos)

		if self.DomainName is not None and len(self.DomainName) > 0:
			data = self.DomainName.encode('utf-16le')
			self.DomainNameFields = Fields(len(data), payload_pos)
			payload += data
			payload_pos += len(data)
		else:
			self.DomainNameFields = Fields(0, payload_pos)

		if self.UserName is not None and len(self.UserName) > 0:
			data = self.UserName.encode('utf-16le')
			self.UserNameFields = Fields(len(data), payload_pos)
			payload += data
			payload_pos += len(data)
		else:
			self.UserNameFields = Fields(0, payload_pos)

		if self.Workstation is not None and len(self.Workstation) > 0:
			data = self.Workstation.encode('utf-16le')
			self.WorkstationFields = Fields(len(data), payload_pos)
			payload += data
			payload_pos += len(data)
		else:
			self.WorkstationFields = Fields(0, payload_pos)

		if self.EncryptedRandomSession is not None:
			data = self.EncryptedRandomSession
			self.EncryptedRandomSessionKeyFields = Fields(len(data), payload_pos)
			payload += data
			payload_pos += len(data)
		else:
			self.EncryptedRandomSessionKeyFields = Fields(0, payload_pos)

		t = self.Signature
		t += self.MessageType.to_bytes(4, byteorder = 'little', signed = False)
		t += self.LmChallengeResponseFields.to_bytes()
		t += self.NtChallengeResponseFields.to_bytes()
		t += self.DomainNameFields.to_bytes()
		t += self.UserNameFields.to_bytes()
		t += self.WorkstationFields.to_bytes()
		t += self.EncryptedRandomSessionKeyFields.to_bytes()
		t += self.NegotiateFlags.to_bytes(4, byteorder = 'little', signed = False)
		if self.Version is not None:
			if isinstance(self.Version, bytes):
				t += self.Version
			else:
				t += self.Version.to_bytes()
		if self.MIC is not None:
			t += self.MIC

		t += payload
		return t


	@staticmethod
	def from_bytes(bbuff,_use_NTLMv2 = True):
		return NTLMAuthenticate.from_buffer(io.BytesIO(bbuff), _use_NTLMv2 = _use_NTLMv2)

	@staticmethod
	def from_buffer(buff, _use_NTLMv2 = True):
		auth = NTLMAuthenticate(_use_NTLMv2)
		auth.Signature    = buff.read(8)
		auth.MessageType  = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		auth.LmChallengeResponseFields = Fields.from_buffer(buff)
		auth.NtChallengeResponseFields = Fields.from_buffer(buff)
		auth.DomainNameFields = Fields.from_buffer(buff)
		auth.UserNameFields = Fields.from_buffer(buff)
		auth.WorkstationFields = Fields.from_buffer(buff)
		auth.EncryptedRandomSessionKeyFields = Fields.from_buffer(buff)
		auth.NegotiateFlags = NegotiateFlags(int.from_bytes(buff.read(4), byteorder = 'little', signed = False))

		# Read Version as raw 8 bytes first; promote it to a Version object only
		# if NEGOTIATE_VERSION is set, otherwise keep the raw bytes around so that
		# to_bytes()/to_bytes_full() can re-emit them verbatim.
		versiondata = buff.read(8)
		if auth.NegotiateFlags & NegotiateFlags.NEGOTIATE_VERSION:
			auth.Version = Version.from_bytes(versiondata)
		else:
			auth.Version = versiondata

		currPos = buff.tell()

		# Decide v1 vs v2 based on the NT challenge length: an NTLMv2 response is
		# variable length and always exceeds 24 bytes, while an LMv2 response is
		# exactly 24 bytes (so it can't be detected from its own length). Parse
		# the LM and NT fields with matching versions to keep them consistent for
		# downstream consumers (e.g. credential extraction).
		use_v2 = auth._use_NTLMv2 and auth.NtChallengeResponseFields.length > 24

		if use_v2:
			buff.seek(auth.LmChallengeResponseFields.offset, io.SEEK_SET)
			auth.LMChallenge = LMv2Response.from_buffer(buff)
		else:
			buff.seek(auth.LmChallengeResponseFields.offset, io.SEEK_SET)
			auth.LMChallenge = LMResponse.from_buffer(buff)

		if use_v2:
			buff.seek(auth.NtChallengeResponseFields.offset, io.SEEK_SET)
			auth.NTChallenge = NTLMv2Response.from_buffer(buff)
			# MIC is only present when the client advertised MIC_PRESENT in the
			# NTv2 client challenge AVPairs (MS-NLMP 2.2.2.10). It sits between
			# the header (incl. Version) and the variable-length payload.
			if AVPAIRType.MsvAvFlags in auth.NTChallenge.ChallengeFromClinet.Details:
				if MsvAvFlags.MIC_PRESENT in auth.NTChallenge.ChallengeFromClinet.Details[AVPAIRType.MsvAvFlags]:
					buff.seek(currPos, io.SEEK_SET)
					auth.MIC = buff.read(16)
					currPos += 16
		else:
			buff.seek(auth.NtChallengeResponseFields.offset, io.SEEK_SET)
			auth.NTChallenge = NTLMv1Response.from_buffer(buff)

		buff.seek(auth.DomainNameFields.offset,io.SEEK_SET)
		auth.DomainName = buff.read(auth.DomainNameFields.length).decode('utf-16le')

		buff.seek(auth.UserNameFields.offset,io.SEEK_SET)
		auth.UserName = buff.read(auth.UserNameFields.length).decode('utf-16le')

		buff.seek(auth.WorkstationFields.offset,io.SEEK_SET)
		auth.Workstation = buff.read(auth.WorkstationFields.length).decode('utf-16le')

		buff.seek(auth.EncryptedRandomSessionKeyFields.offset,io.SEEK_SET)
		auth.EncryptedRandomSession = buff.read(auth.EncryptedRandomSessionKeyFields.length)

		buff.seek(currPos, io.SEEK_SET)
		auth.Payload = buff.read()

		return auth

	def __repr__(self):
		t  = '== NTLMAuthenticate ==\r\n'
		t += 'Signature     : %s\r\n' % repr(self.Signature)
		t += 'MessageType   : %s\r\n' % repr(self.MessageType)
		t += 'NegotiateFlags: %s\r\n' % repr(self.NegotiateFlags)
		t += 'Version       : %s\r\n' % repr(self.Version)
		t += 'MIC           : %s\r\n' % repr(self.MIC.hex() if self.MIC else 'None')
		t += 'LMChallenge   : %s\r\n' % repr(self.LMChallenge)
		t += 'NTChallenge   : %s\r\n' % repr(self.NTChallenge)
		t += 'DomainName    : %s\r\n' % repr(self.DomainName)
		t += 'UserName      : %s\r\n' % repr(self.UserName)
		t += 'Workstation   : %s\r\n' % repr(self.Workstation)
		t += 'EncryptedRandomSession: %s\r\n' % repr(self.EncryptedRandomSession.hex() if self.EncryptedRandomSession else 'None')
		return t

def test():
	test_reconstrut()
	test_construct()
	test_2()
	
def test_2():
	data = bytes.fromhex('4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 006c 00 00 00 54 00 54 00 84 00 00 00 0c 00 0c 0048 00 00 00 08 00 08 00 54 00 00 00 10 00 10 005c 00 00 00 10 00 10 00 d8 00 00 00 35 82 88 e205 01 28 0a 00 00 00 0f 44 00 6f 00 6d 00 61 0069 00 6e 00 55 00 73 00 65 00 72 00 43 00 4f 004d 00 50 00 55 00 54 00 45 00 52 00 86 c3 50 97ac 9c ec 10 25 54 76 4a 57 cc cc 19 aa aa aa aaaa aa aa aa 68 cd 0a b8 51 e5 1c 96 aa bc 92 7beb ef 6a 1c 01 01 00 00 00 00 00 00 00 00 00 0000 00 00 00 aa aa aa aa aa aa aa aa 00 00 00 0002 00 0c 00 44 00 6f 00 6d 00 61 00 69 00 6e 0001 00 0c 00 53 00 65 00 72 00 76 00 65 00 72 0000 00 00 00 00 00 00 00 c5 da d2 54 4f c9 79 9094 ce 1c e9 0b c9 d0 3e')
	challenge = NTLMAuthenticate.from_bytes(data)
	print(repr(challenge))
	
def test_reconstrut(data = None):
	print('=== reconstruct===')
	if not data:
		auth_test_data = bytes.fromhex('4e544c4d5353500003000000180018007c000000180118019400000008000800580000000c000c0060000000100010006c00000010001000ac010000158288e20a00d73a0000000f0d98eb57e9c52820709c99b98ca321a15400450053005400760069006300740069006d00570049004e0031003000580036003400000000000000000000000000000000000000000000000000fade3940b9381c53c91ddcdd0d44000b0101000000000000aec600bfc5fdd4011bfa20699d7628730000000002000800540045005300540001001200570049004e003200300031003900410044000400120074006500730074002e0063006f007200700003002600570049004e003200300031003900410044002e0074006500730074002e0063006f007200700007000800aec600bfc5fdd40106000400020000000800300030000000000000000000000000200000527d27f234de743760966384d36f61ae2aa4fc2a380699f8caa600011b486d890a0010000000000000000000000000000000000009001e0063006900660073002f00310030002e00310030002e00310030002e003200000000000000000000000000fd67edfb41c09465a91fd733deb0b55b')
	else:
		auth_test_data = data
	challenge = NTLMAuthenticate.from_bytes(auth_test_data)
	print(repr(challenge))
	auth_test_data_verify = challenge.to_bytes()
	print('====== reconstructed ====')
	print(hexdump(auth_test_data_verify))
	print('====== original ====')
	print(hexdump(auth_test_data))
	assert auth_test_data == auth_test_data_verify
	
	
def test_construct():
	pass
	
if __name__ == '__main__':
	from asyauth.utils.hexdump import hexdump
	
	test()