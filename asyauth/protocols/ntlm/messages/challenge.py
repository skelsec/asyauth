import os
import io
import base64

from asyauth.protocols.ntlm.structures.fields import Fields
from asyauth.protocols.ntlm.structures.negotiate_flags import NegotiateFlags
from asyauth.protocols.ntlm.structures.version import Version
from asyauth.protocols.ntlm.structures.avpair import AVPairs

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786
class NTLMChallenge:
	def __init__(self):
		self.Signature         = b'NTLMSSP\x00'
		self.MessageType       = 2
		self.TargetNameFields  = None
		self.NegotiateFlags    = None
		self.ServerChallenge   = None
		self.Reserved          = b'\x00'*8
		self.TargetInfoFields  = None
		self.Version           = None
		self.Payload           = None

		self.TargetName        = None
		self.TargetInfo        = None
		
		
	@staticmethod
	def from_bytes(bbuff):
		return NTLMChallenge.from_buffer(io.BytesIO(bbuff))

	@staticmethod
	def from_buffer(buff):
		t = NTLMChallenge()
		t.Signature         = buff.read(8)
		t.MessageType       = int.from_bytes(buff.read(4), byteorder = 'little', signed = False)
		t.TargetNameFields  = Fields.from_buffer(buff)
		t.NegotiateFlags    = NegotiateFlags(int.from_bytes(buff.read(4), byteorder = 'little', signed = False))
		t.ServerChallenge   = buff.read(8)
		t.Reserved          = buff.read(8)
		t.TargetInfoFields  = Fields.from_buffer(buff)
		
		if t.NegotiateFlags & NegotiateFlags.NEGOTIATE_VERSION: 
			t.Version = Version.from_buffer(buff)
			
		currPos = buff.tell()
		t.Payload = buff.read()
			
		if t.TargetNameFields.length != 0:
			buff.seek(t.TargetNameFields.offset, io.SEEK_SET)
			raw_data = buff.read(t.TargetNameFields.length)
			try:
				t.TargetName = raw_data.decode('utf-16le')
			except UnicodeDecodeError:
				# yet another cool bug. 
				t.TargetName = raw_data.decode('utf-8')
				
		if t.TargetInfoFields.length != 0:
			buff.seek(t.TargetInfoFields.offset, io.SEEK_SET)
			raw_data = buff.read(t.TargetInfoFields.length)
			t.TargetInfo = AVPairs.from_bytes(raw_data)
			
		
		
		return t
	
	@staticmethod
	def construct(challenge = None, targetName = None, targetInfo = None, version = None, flags = None):
		"""
		Construct a new NTLMChallenge message.
		
		Args:
			challenge: 8-byte server challenge (defaults to random)
			targetName: Target name string (optional)
			targetInfo: AVPairs object for target info (optional) 
			version: Version object (optional)
			flags: NegotiateFlags object (required if version is provided)
		
		Returns:
			NTLMChallenge: Constructed challenge message
		"""
		# Generate random challenge if not provided
		if challenge is None:
			challenge = os.urandom(8)
		
		# Validate challenge length
		if len(challenge) != 8:
			raise ValueError("Server challenge must be exactly 8 bytes")
		
		# Create new instance
		t = NTLMChallenge()
		t.ServerChallenge = challenge
		t.Version = version
		
		# Handle flags - set NEGOTIATE_VERSION if version is provided
		if flags is None:
			flags = NegotiateFlags(0)
		elif not isinstance(flags, NegotiateFlags):
			flags = NegotiateFlags(flags)
		
		if version is not None:
			flags |= NegotiateFlags.NEGOTIATE_VERSION
		
		t.NegotiateFlags = flags
		
		# Calculate payload position after fixed fields
		# Fixed header: 8 (sig) + 4 (type) + 8 (targetname fields) + 4 (flags) + 8 (challenge) + 8 (reserved) + 8 (targetinfo fields) = 48
		payload_pos = 48
		if version is not None:
			payload_pos += 8  # Version structure is 8 bytes
		
		# Handle target name
		if targetName is not None:
			target_name_data = targetName.encode('utf-16le')
			t.TargetName = targetName
			t.TargetNameFields = Fields(len(target_name_data), payload_pos)
			payload_pos += len(target_name_data)
		else:
			t.TargetName = ''
			t.TargetNameFields = Fields(0, payload_pos)
		
		# Handle target info
		if targetInfo is not None:
			target_info_data = targetInfo.to_bytes()
			t.TargetInfo = targetInfo
			t.TargetInfoFields = Fields(len(target_info_data), payload_pos)
		else:
			# Create empty AVPairs with just EOL marker
			t.TargetInfo = AVPairs()
			target_info_data = t.TargetInfo.to_bytes()
			t.TargetInfoFields = Fields(len(target_info_data), payload_pos)
		
		# Build payload
		t.Payload = b''
		if targetName is not None:
			t.Payload += targetName.encode('utf-16le')
		if targetInfo is not None:
			t.Payload += targetInfo.to_bytes()
		else:
			t.Payload += t.TargetInfo.to_bytes()
		
		return t

	def to_bytes(self):
		tn = self.TargetName.encode('utf-16le')
		ti = self.TargetInfo.to_bytes()

		buff  = self.Signature
		buff += self.MessageType.to_bytes(4, byteorder = 'little', signed = False)
		buff += self.TargetNameFields.to_bytes()
		buff += self.NegotiateFlags.to_bytes(4, byteorder = 'little', signed = False)
		buff += self.ServerChallenge
		buff += self.Reserved
		buff += self.TargetInfoFields.to_bytes()
		if self.Version:
			buff += self.Version.to_bytes()
		buff += self.Payload

		return buff

	def __repr__(self):
		t  = '== NTLMChallenge ==\r\n'
		t += 'Signature      : %s\r\n' % repr(self.Signature)
		t += 'MessageType    : %s\r\n' % repr(self.MessageType)
		t += 'ServerChallenge: %s\r\n' % repr(self.ServerChallenge)
		t += 'TargetName     : %s\r\n' % repr(self.TargetName)
		t += 'TargetInfo     : %s\r\n' % repr(self.TargetInfo)
		return t

	def toBase64(self):
		return base64.b64encode(self.to_bytes()).decode('ascii')


def test():
	test_reconstrut()
	test_construct()
	test_template()
	
def test_reconstrut(data = None):
	try:
		from asyauth.utils.hexdump import hexdump
	except ImportError:
		def hexdump(data):
			return data.hex()
	
	print('=== reconstruct===')
	if not data:
		challenge_test_data = bytes.fromhex('4e544c4d53535000020000000800080038000000158289e2a7314a557bdb11bf000000000000000072007200400000000a0063450000000f540045005300540002000800540045005300540001001200570049004e003200300031003900410044000400120074006500730074002e0063006f007200700003002600570049004e003200300031003900410044002e0074006500730074002e0063006f007200700007000800aec600bfc5fdd40100000000')
	else:
		challenge_test_data = data
	challenge = NTLMChallenge.from_bytes(challenge_test_data)
	print(repr(challenge))
	challenge_test_data_verify = challenge.to_bytes()
	print('====== reconstructed ====')
	print(hexdump(challenge_test_data_verify))
	print('====== original ====')
	print(hexdump(challenge_test_data))
	assert challenge_test_data == challenge_test_data_verify
	
def test_template():
	
	#challenge = NTLMChallenge.construct_from_template('Windows2003')
	#test_reconstrut(challenge.to_bytes())
	pass
	
def test_construct():
	print('=== test_construct ===')
	
	# Test basic construction with minimal parameters
	challenge1 = NTLMChallenge.construct()
	print('Basic construct test passed')
	
	# Test with custom challenge
	custom_challenge = b'\x01\x02\x03\x04\x05\x06\x07\x08'
	challenge2 = NTLMChallenge.construct(challenge=custom_challenge)
	assert challenge2.ServerChallenge == custom_challenge
	print('Custom challenge test passed')
	
	# Test with target name
	challenge3 = NTLMChallenge.construct(targetName="DOMAIN")
	assert challenge3.TargetName == "DOMAIN"
	print('Target name test passed')
	
	# Test with target info
	from asyauth.protocols.ntlm.structures.avpair import AVPairs, AVPAIRType
	target_info = AVPairs()
	target_info[AVPAIRType.MsvAvNbDomainName] = "DOMAIN"
	challenge4 = NTLMChallenge.construct(targetInfo=target_info)
	assert challenge4.TargetInfo[AVPAIRType.MsvAvNbDomainName] == "DOMAIN"
	print('Target info test passed')
	
	# Test roundtrip (construct -> to_bytes -> from_bytes)
	challenge5 = NTLMChallenge.construct(
		challenge=custom_challenge,
		targetName="TEST",
		targetInfo=target_info
	)
	data = challenge5.to_bytes()
	challenge6 = NTLMChallenge.from_bytes(data)
	assert challenge6.ServerChallenge == custom_challenge
	assert challenge6.TargetName == "TEST"
	print('Roundtrip test passed')
	
	print('All construct tests passed!')
	
if __name__ == '__main__':
	from asyauth.utils.hexdump import hexdump
	
	test()