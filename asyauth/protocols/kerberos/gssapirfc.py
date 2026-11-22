
# Kerberos V5 GSSAPI per-message tokens as the RFCs describe them.
#
# The classes in gssapi.py / gssapismb.py follow what Windows does on SMB, LDAP
# and DCERPC (DCE style, fixed RRC, initiator side only). The ones here are
# meant for peers using MIT krb5 or Heimdal, eg. RPCSEC_GSS (NFS).
#
# https://datatracker.ietf.org/doc/html/rfc4121  (AES, "CFX" tokens)
# https://datatracker.ietf.org/doc/html/rfc1964  (DES, and the token framing for the old token types)
# https://datatracker.ietf.org/doc/html/draft-raeburn-krb5-gssapi-krb5-3des-01  (3DES)
# https://datatracker.ietf.org/doc/html/rfc4757  (RC4-HMAC)

import enum
import os

from asn1crypto.core import ObjectIdentifier

from minikerberos.protocol import encryption
from unicrypto import hmac
from unicrypto.hashlib import md5
from unicrypto.symmetric import RC4, DES, TDES, MODE_CBC


GSS_KRB5_MECH_OID = '1.2.840.113554.1.2.2'

TOK_ID_AP_REQ = b'\x01\x00'
TOK_ID_AP_REP = b'\x02\x00'
TOK_ID_ERROR  = b'\x03\x00'
TOK_ID_MIC    = b'\x04\x04'
TOK_ID_WRAP   = b'\x05\x04'
TOK_ID_MIC_V1  = b'\x01\x01'
TOK_ID_WRAP_V1 = b'\x02\x01'

class KG_USAGE(enum.Enum):
	ACCEPTOR_SEAL  = 22
	ACCEPTOR_SIGN  = 23
	INITIATOR_SEAL = 24
	INITIATOR_SIGN = 25

# RFC4121 4.2.2
class CFXFlags(enum.IntFlag):
	SentByAcceptor = 1
	Sealed = 2
	AcceptorSubkey = 4

def gss_frame(data:bytes, oid:str = GSS_KRB5_MECH_OID):
	"""Adds the mechanism independent framing (RFC2743 3.1) to a mechanism token"""
	t = ObjectIdentifier(oid).dump() + data
	if len(t) <= 127:
		length = bytes([len(t)])
	else:
		length = len(t).to_bytes((len(t).bit_length() + 7) // 8, 'big', signed = False)
		length = bytes([0x80 | len(length)]) + length
	return b'\x60' + length + t

def gss_unframe(token:bytes, oid:str = GSS_KRB5_MECH_OID):
	"""Removes the mechanism independent framing, returns the inner token"""
	if token[:1] != b'\x60' or len(token) < 2:
		raise Exception('Not a GSSAPI token')
	pos = 2
	length = token[1]
	if length > 127:
		pos += length - 128
		if length == 128 or len(token) < pos:
			raise Exception('Incorrect GSSAPI token length')
		length = int.from_bytes(token[2:pos], 'big', signed = False)
	if length != len(token) - pos:
		raise Exception('Incorrect GSSAPI token length')
	oid_data = ObjectIdentifier(oid).dump()
	if token[pos: pos + len(oid_data)] != oid_data:
		raise Exception('Unexpected mechanism OID in GSSAPI token')
	return token[pos + len(oid_data):]

def rotate_right(data:bytes, count:int):
	if len(data) == 0:
		return data
	count %= len(data)
	return data[len(data) - count:] + data[:len(data) - count]

def rotate_left(data:bytes, count:int):
	if len(data) == 0:
		return data
	count %= len(data)
	return data[count:] + data[:count]

class GSSAPI_RFC4121:
	"""
	RFC4121 section 4.2 per-message tokens for the RFC3961 simplified profile
	enctypes (AES128/AES256 with HMAC-SHA1-96).

	key: the context key. This is the acceptor's subkey if the AP-REP had one,
		otherwise the initiator's subkey, otherwise the ticket session key.
	is_initiator: which side of the context we are
	acceptor_subkey: True if key is the subkey asserted by the acceptor

	This class holds no sequence number state, that is kept by the caller.
	"""
	def __init__(self, key, cipher_type, checksum_profile, is_initiator = True, acceptor_subkey = False):
		self.key = key
		self.cipher_type = cipher_type
		self.checksum_profile = checksum_profile
		self.is_initiator = is_initiator
		self.acceptor_subkey = acceptor_subkey

		if self.is_initiator is True:
			self.usage_send_sign = KG_USAGE.INITIATOR_SIGN.value
			self.usage_send_seal = KG_USAGE.INITIATOR_SEAL.value
			self.usage_recv_sign = KG_USAGE.ACCEPTOR_SIGN.value
			self.usage_recv_seal = KG_USAGE.ACCEPTOR_SEAL.value
		else:
			self.usage_send_sign = KG_USAGE.ACCEPTOR_SIGN.value
			self.usage_send_seal = KG_USAGE.ACCEPTOR_SEAL.value
			self.usage_recv_sign = KG_USAGE.INITIATOR_SIGN.value
			self.usage_recv_seal = KG_USAGE.INITIATOR_SEAL.value

	def get_send_flags(self):
		flags = CFXFlags(0)
		if self.is_initiator is False:
			flags |= CFXFlags.SentByAcceptor
		if self.acceptor_subkey is True:
			flags |= CFXFlags.AcceptorSubkey
		return flags

	def check_recv_flags(self, flags):
		flags = CFXFlags(flags & 7)
		if (CFXFlags.SentByAcceptor in flags) != self.is_initiator:
			raise Exception('Token direction mismatch (reflected token?)')
		if (CFXFlags.AcceptorSubkey in flags) != self.acceptor_subkey:
			raise Exception('Token AcceptorSubkey flag does not match the context')
		return flags

	def GSS_GetMIC(self, data:bytes, seq_num:int):
		"""Returns the MIC token for data"""
		try:
			hdr  = TOK_ID_MIC
			hdr += bytes([self.get_send_flags()])
			hdr += b'\xFF' * 5
			hdr += seq_num.to_bytes(8, 'big', signed = False)
			cksum = self.checksum_profile.checksum(self.key, self.usage_send_sign, data + hdr)
			return hdr + cksum, None
		except Exception as e:
			return None, e

	def GSS_VerifyMIC(self, data:bytes, token:bytes):
		"""Verifies a MIC token created by the peer. Returns the sequence number of the token"""
		try:
			if len(token) != 16 + self.checksum_profile.macsize:
				raise Exception('Incorrect MIC token length')
			hdr = token[:16]
			if hdr[:2] != TOK_ID_MIC:
				raise Exception('Not a MIC token')
			if hdr[3:8] != b'\xFF' * 5:
				raise Exception('Incorrect filler in MIC token')
			self.check_recv_flags(hdr[2])
			self.checksum_profile.verify(self.key, self.usage_recv_sign, data + hdr, token[16:])
			return int.from_bytes(hdr[8:16], 'big', signed = False), None
		except Exception as e:
			return None, e

	def GSS_Wrap(self, data:bytes, seq_num:int, confidential:bool = True):
		"""Returns the Wrap token carrying data"""
		try:
			flags = self.get_send_flags()
			if confidential is True:
				flags |= CFXFlags.Sealed
				# EC is the amount of filler after the data. None of the supported
				# enctypes need any. RRC is 0, the token is sent unrotated
				hdr  = TOK_ID_WRAP + bytes([flags]) + b'\xFF'
				hdr += b'\x00\x00' + b'\x00\x00'
				hdr += seq_num.to_bytes(8, 'big', signed = False)
				cipher_text = self.cipher_type.encrypt(self.key, self.usage_send_seal, data + hdr, None)
				return hdr + cipher_text, None

			# checksum is calculated with EC and RRC being zero,
			# then EC is set to the size of the checksum
			hdr  = TOK_ID_WRAP + bytes([flags]) + b'\xFF'
			hdr += b'\x00\x00' + b'\x00\x00'
			hdr += seq_num.to_bytes(8, 'big', signed = False)
			cksum = self.checksum_profile.checksum(self.key, self.usage_send_seal, data + hdr)
			hdr = hdr[:4] + len(cksum).to_bytes(2, 'big', signed = False) + hdr[6:]
			return hdr + data + cksum, None
		except Exception as e:
			return None, e

	def GSS_Unwrap(self, token:bytes):
		"""
		Processes a Wrap token created by the peer.
		Returns the data, wether it was encrypted and the sequence number of the token
		"""
		try:
			if len(token) < 16:
				raise Exception('Wrap token too short')
			hdr = token[:16]
			if hdr[:2] != TOK_ID_WRAP:
				raise Exception('Not a Wrap token')
			if hdr[3:4] != b'\xFF':
				raise Exception('Incorrect filler in Wrap token')
			flags = self.check_recv_flags(hdr[2])
			ec  = int.from_bytes(hdr[4:6], 'big', signed = False)
			rrc = int.from_bytes(hdr[6:8], 'big', signed = False)
			seq_num = int.from_bytes(hdr[8:16], 'big', signed = False)
			body = rotate_left(token[16:], rrc)

			if CFXFlags.Sealed in flags:
				plain_text = self.cipher_type.decrypt(self.key, self.usage_recv_seal, body)
				if len(plain_text) < 16 + ec:
					raise Exception('Wrap token too short')
				# the encrypted copy of the header has RRC zeroed
				if plain_text[-16:] != hdr[:6] + b'\x00\x00' + hdr[8:]:
					raise Exception('Wrap token header mismatch')
				return plain_text[:len(plain_text) - (16 + ec)], True, seq_num, None

			if ec != self.checksum_profile.macsize or len(body) < ec:
				raise Exception('Incorrect checksum length in Wrap token')
			data = body[:len(body) - ec]
			hdr_ck = hdr[:4] + b'\x00\x00' + b'\x00\x00' + hdr[8:]
			self.checksum_profile.verify(self.key, self.usage_recv_seal, data + hdr_ck, body[len(body) - ec:])
			return data, False, seq_num, None
		except Exception as e:
			return None, None, None, e

class GSSAPI_RFC4757:
	"""
	RFC4757 section 7 per-message tokens for RC4-HMAC. These are the RFC1964
	style tokens: they carry the mechanism independent framing and have
	32 bit sequence numbers.

	key: the context key. This is the initiator's subkey if the authenticator
		had one, otherwise the ticket session key.
	"""
	def __init__(self, key, is_initiator = True):
		self.key = key
		self.is_initiator = is_initiator
		self.send_direction = b'\x00' * 4 if is_initiator is True else b'\xFF' * 4
		self.recv_direction = b'\xFF' * 4 if is_initiator is True else b'\x00' * 4

	def hmac_md5(self, key, data):
		ctx = hmac.new(key, digestmod = 'md5')
		ctx.update(data)
		return ctx.digest()

	def get_ksign(self):
		return self.hmac_md5(self.key.contents, b'signaturekey\0')

	def get_kseq(self, cksum):
		return self.hmac_md5(self.hmac_md5(self.key.contents, b'\x00' * 4), cksum)

	def get_kcrypt(self, seq):
		klocal = bytes([b ^ 0xF0 for b in self.key.contents])
		return self.hmac_md5(self.hmac_md5(klocal, b'\x00' * 4), seq)

	def get_checksum(self, usage, data):
		temp = md5(usage.to_bytes(4, 'little', signed = False) + data).digest()
		return self.hmac_md5(self.get_ksign(), temp)[:8]

	def decrypt_seq(self, snd_seq, cksum):
		snd_seq = RC4(self.get_kseq(cksum)).decrypt(snd_seq)
		if snd_seq[4:] != self.recv_direction:
			raise Exception('Token direction mismatch (reflected token?)')
		return snd_seq[:4]

	def GSS_GetMIC(self, data:bytes, seq_num:int):
		"""Returns the MIC token for data"""
		try:
			hdr = TOK_ID_MIC_V1 + b'\x11\x00' + b'\xFF' * 4
			cksum = self.get_checksum(15, hdr + data)
			snd_seq = (seq_num & 0xFFFFFFFF).to_bytes(4, 'big', signed = False) + self.send_direction
			snd_seq = RC4(self.get_kseq(cksum)).encrypt(snd_seq)
			return gss_frame(hdr + snd_seq + cksum), None
		except Exception as e:
			return None, e

	def GSS_VerifyMIC(self, data:bytes, token:bytes):
		"""Verifies a MIC token created by the peer. Returns the sequence number of the token"""
		try:
			token = gss_unframe(token)
			if len(token) != 24:
				raise Exception('Incorrect MIC token length')
			hdr = token[:8]
			if hdr != TOK_ID_MIC_V1 + b'\x11\x00' + b'\xFF' * 4:
				raise Exception('Not an RC4-HMAC MIC token')
			cksum = token[16:24]
			if encryption._mac_equal(cksum, self.get_checksum(15, hdr + data)) is False:
				raise Exception('MIC token checksum verification failure')
			seq = self.decrypt_seq(token[8:16], cksum)
			return int.from_bytes(seq, 'big', signed = False), None
		except Exception as e:
			return None, e

	def GSS_Wrap(self, data:bytes, seq_num:int, confidential:bool = True):
		"""Returns the Wrap token carrying data"""
		try:
			seal_alg = b'\x10\x00' if confidential is True else b'\xFF\xFF'
			hdr = TOK_ID_WRAP_V1 + b'\x11\x00' + seal_alg + b'\xFF' * 2
			# RC4 is a stream cipher, so the RFC1964 padding is one byte
			data += b'\x01'
			confounder = os.urandom(8)
			cksum = self.get_checksum(13, hdr + confounder + data)
			seq = (seq_num & 0xFFFFFFFF).to_bytes(4, 'big', signed = False)
			if confidential is True:
				rc4 = RC4(self.get_kcrypt(seq))
				confounder = rc4.encrypt(confounder)
				data = rc4.encrypt(data)
			snd_seq = RC4(self.get_kseq(cksum)).encrypt(seq + self.send_direction)
			return gss_frame(hdr + snd_seq + cksum + confounder + data), None
		except Exception as e:
			return None, e

	def GSS_Unwrap(self, token:bytes):
		"""
		Processes a Wrap token created by the peer.
		Returns the data, wether it was encrypted and the sequence number of the token
		"""
		try:
			token = gss_unframe(token)
			if len(token) < 33:
				raise Exception('Wrap token too short')
			hdr = token[:8]
			if hdr[:4] != TOK_ID_WRAP_V1 + b'\x11\x00' or hdr[6:8] != b'\xFF' * 2:
				raise Exception('Not an RC4-HMAC Wrap token')
			if hdr[4:6] == b'\x10\x00':
				confidential = True
			elif hdr[4:6] == b'\xFF\xFF':
				confidential = False
			else:
				raise Exception('Unsupported SEAL_ALG in Wrap token')
			cksum = token[16:24]
			confounder = token[24:32]
			data = token[32:]
			seq = self.decrypt_seq(token[8:16], cksum)
			if confidential is True:
				rc4 = RC4(self.get_kcrypt(seq))
				confounder = rc4.decrypt(confounder)
				data = rc4.decrypt(data)
			if encryption._mac_equal(cksum, self.get_checksum(13, hdr + confounder + data)) is False:
				raise Exception('Wrap token checksum verification failure')
			pad = data[-1]
			if pad < 1 or pad > 8 or pad > len(data):
				raise Exception('Incorrect padding in Wrap token')
			return data[:len(data) - pad], confidential, int.from_bytes(seq, 'big', signed = False), None
		except Exception as e:
			return None, None, None, e

class GSSAPI_RFC1964:
	"""
	RFC1964 per-message tokens for the single DES enctypes (DES MAC MD5 checksum,
	DES seal) and their 3DES version for des3-cbc-sha1 (HMAC SHA1 DES3 KD
	checksum, DES3 seal).

	key: the context key. This is the initiator's subkey if the authenticator
		had one, otherwise the ticket session key.
	"""
	def __init__(self, key, is_initiator = True):
		self.key = key
		self.is_initiator = is_initiator
		self.send_direction = b'\x00' * 4 if is_initiator is True else b'\xFF' * 4
		self.recv_direction = b'\xFF' * 4 if is_initiator is True else b'\x00' * 4
		if key.enctype == encryption.Enctype.DES3:
			self.sgn_alg = b'\x04\x00'
			self.seal_alg = b'\x02\x00'
			self.cksum_len = 20
			self.cipher = TDES
			self.seal_key = key.contents
		else:
			self.sgn_alg = b'\x00\x00'
			self.seal_alg = b'\x00\x00'
			self.cksum_len = 8
			self.cipher = DES
			self.seal_key = bytes([b ^ 0xF0 for b in key.contents])

	def get_checksum(self, data):
		if self.cipher is TDES:
			return encryption._SHA1DES3.checksum(self.key, KG_USAGE.ACCEPTOR_SIGN.value, data)
		# DES MAC MD5 is the last block of the encrypted MD5 hash
		return self.cipher(self.key.contents, MODE_CBC, b'\x00' * 8).encrypt(md5(data).digest())[8:]

	def encrypt_seq(self, seq_num, cksum):
		snd_seq = (seq_num & 0xFFFFFFFF).to_bytes(4, 'little', signed = False) + self.send_direction
		return self.cipher(self.key.contents, MODE_CBC, cksum[:8]).encrypt(snd_seq)

	def decrypt_seq(self, snd_seq, cksum):
		snd_seq = self.cipher(self.key.contents, MODE_CBC, cksum[:8]).decrypt(snd_seq)
		if snd_seq[4:] != self.recv_direction:
			raise Exception('Token direction mismatch (reflected token?)')
		return int.from_bytes(snd_seq[:4], 'little', signed = False)

	def GSS_GetMIC(self, data:bytes, seq_num:int):
		"""Returns the MIC token for data"""
		try:
			hdr = TOK_ID_MIC_V1 + self.sgn_alg + b'\xFF' * 4
			cksum = self.get_checksum(hdr + data)
			return gss_frame(hdr + self.encrypt_seq(seq_num, cksum) + cksum), None
		except Exception as e:
			return None, e

	def GSS_VerifyMIC(self, data:bytes, token:bytes):
		"""Verifies a MIC token created by the peer. Returns the sequence number of the token"""
		try:
			token = gss_unframe(token)
			if len(token) != 16 + self.cksum_len:
				raise Exception('Incorrect MIC token length')
			hdr = token[:8]
			if hdr != TOK_ID_MIC_V1 + self.sgn_alg + b'\xFF' * 4:
				raise Exception('Not a MIC token of this enctype')
			cksum = token[16:]
			if encryption._mac_equal(cksum, self.get_checksum(hdr + data)) is False:
				raise Exception('MIC token checksum verification failure')
			return self.decrypt_seq(token[8:16], cksum), None
		except Exception as e:
			return None, e

	def GSS_Wrap(self, data:bytes, seq_num:int, confidential:bool = True):
		"""Returns the Wrap token carrying data"""
		try:
			seal_alg = self.seal_alg if confidential is True else b'\xFF\xFF'
			hdr = TOK_ID_WRAP_V1 + self.sgn_alg + seal_alg + b'\xFF' * 2
			pad = 8 - (len(data) % 8)
			body = os.urandom(8) + data + bytes([pad]) * pad
			cksum = self.get_checksum(hdr + body)
			if confidential is True:
				body = self.cipher(self.seal_key, MODE_CBC, b'\x00' * 8).encrypt(body)
			return gss_frame(hdr + self.encrypt_seq(seq_num, cksum) + cksum + body), None
		except Exception as e:
			return None, e

	def GSS_Unwrap(self, token:bytes):
		"""
		Processes a Wrap token created by the peer.
		Returns the data, wether it was encrypted and the sequence number of the token
		"""
		try:
			token = gss_unframe(token)
			if len(token) < 16 + self.cksum_len + 16:
				raise Exception('Wrap token too short')
			hdr = token[:8]
			if hdr[:4] != TOK_ID_WRAP_V1 + self.sgn_alg or hdr[6:8] != b'\xFF' * 2:
				raise Exception('Not a Wrap token of this enctype')
			if hdr[4:6] == self.seal_alg:
				confidential = True
			elif hdr[4:6] == b'\xFF\xFF':
				confidential = False
			else:
				raise Exception('Unsupported SEAL_ALG in Wrap token')
			cksum = token[16:16 + self.cksum_len]
			body = token[16 + self.cksum_len:]
			if len(body) % 8 != 0:
				raise Exception('Incorrect Wrap token length')
			seq_num = self.decrypt_seq(token[8:16], cksum)
			if confidential is True:
				body = self.cipher(self.seal_key, MODE_CBC, b'\x00' * 8).decrypt(body)
			if encryption._mac_equal(cksum, self.get_checksum(hdr + body)) is False:
				raise Exception('Wrap token checksum verification failure')
			pad = body[-1]
			if pad < 1 or pad > 8 or pad > len(body) - 8:
				raise Exception('Incorrect padding in Wrap token')
			return body[8:len(body) - pad], confidential, seq_num, None
		except Exception as e:
			return None, None, None, e

def get_gssapi_rfc(key, is_initiator = True, acceptor_subkey = False):
	if key.enctype == encryption.Enctype.AES256:
		return GSSAPI_RFC4121(key, encryption._AES256CTS, encryption._SHA1AES256, is_initiator = is_initiator, acceptor_subkey = acceptor_subkey)
	elif key.enctype == encryption.Enctype.AES128:
		return GSSAPI_RFC4121(key, encryption._AES128CTS, encryption._SHA1AES128, is_initiator = is_initiator, acceptor_subkey = acceptor_subkey)
	elif key.enctype == encryption.Enctype.RC4:
		return GSSAPI_RFC4757(key, is_initiator = is_initiator)
	elif key.enctype in (encryption.Enctype.DES3, encryption.Enctype.DES_MD5, encryption.Enctype.DES_MD4, encryption.Enctype.DES_CRC):
		return GSSAPI_RFC1964(key, is_initiator = is_initiator)
	else:
		raise Exception('Unsupported etype %s' % key.enctype)
