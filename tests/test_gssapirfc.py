# Offline tests of the RFC4121 / RFC4757 / RFC1964 per-message tokens.
#
# The RFCs have no test vectors for the tokens themselves, so the known answers
# here were produced by MIT krb5 (see tests/lab/genvectors.py).
import os
import json

import pytest

from minikerberos.protocol.encryption import Key, Enctype
from asyauth.protocols.kerberos.gssapirfc import get_gssapi_rfc, gss_frame, gss_unframe, \
	rotate_right, GSSAPI_RFC4121

VECTORS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'testdata')
# mit_gss_vectors_legacy.json is from MIT krb5 1.17, the last one with single DES
VECTORS_FILES = ['mit_gss_vectors.json', 'mit_gss_vectors_legacy.json']

def get_key(enctype, contents):
	if enctype in (Enctype.DES_CRC, Enctype.DES_MD4):
		# minikerberos has no profile for these, the tokens are the same for all DES enctypes
		key = Key(Enctype.DES_MD5, contents)
		key.enctype = enctype
		return key
	return Key(enctype, contents)

def load_vectors():
	vectors = []
	for fname in VECTORS_FILES:
		with open(os.path.join(VECTORS_DIR, fname), 'r') as f:
			vectors += json.load(f)
	for v in vectors:
		key = bytes.fromhex(v['key'])
		if 'enctype' in v:
			pass
		elif v['initiator'][0]['token'].startswith('60'):
			v['enctype'] = Enctype.RC4
		elif len(key) == 16:
			v['enctype'] = Enctype.AES128
		else:
			v['enctype'] = Enctype.AES256
		v['id'] = '%s-%s' % (v['enctype'], 'acceptorsubkey' if v['acceptor_subkey'] else 'nosubkey')
	return vectors

VECTORS = load_vectors()
KEYS = [
	Key(Enctype.AES256, bytes(range(32))),
	Key(Enctype.AES128, bytes(range(16))),
	Key(Enctype.RC4, bytes(range(16))),
	Key(Enctype.DES3, bytes(range(1, 25))),
	Key(Enctype.DES_MD5, bytes(range(1, 9))),
	get_key(Enctype.DES_CRC, bytes(range(1, 9))),
]
DATA = [b'', b'a', b'0123456789abcde', b'0123456789abcdef', b'0123456789abcdefg', os.urandom(1000)]

def test_vectors_cover_all_etypes():
	ids = [v['id'] for v in VECTORS]
	assert '%s-acceptorsubkey' % Enctype.AES256 in ids
	assert '%s-nosubkey' % Enctype.AES256 in ids
	assert '%s-nosubkey' % Enctype.AES128 in ids
	assert '%s-nosubkey' % Enctype.RC4 in ids
	assert '%s-nosubkey' % Enctype.DES3 in ids
	assert '%s-nosubkey' % Enctype.DES_MD5 in ids
	assert '%s-nosubkey' % Enctype.DES_CRC in ids

@pytest.mark.parametrize('vector', VECTORS, ids = [v['id'] for v in VECTORS])
@pytest.mark.parametrize('sender', ['initiator', 'acceptor'])
def test_mit_vectors(vector, sender):
	key = get_key(vector['enctype'], bytes.fromhex(vector['key']))
	# we are the other side
	receiver = get_gssapi_rfc(key, is_initiator = sender == 'acceptor', acceptor_subkey = vector['acceptor_subkey'])
	same_side = get_gssapi_rfc(key, is_initiator = sender == 'initiator', acceptor_subkey = vector['acceptor_subkey'])
	for entry in vector[sender]:
		data = bytes.fromhex(entry['data'])
		token = bytes.fromhex(entry['token'])
		if entry['type'] == 'mic':
			seq, err = receiver.GSS_VerifyMIC(data, token)
			assert err is None
			# MIC tokens are deterministic
			ours, err = same_side.GSS_GetMIC(data, seq)
			assert err is None
			assert ours == token

			_, err = receiver.GSS_VerifyMIC(data + b'x', token)
			assert err is not None
			# reflected token
			_, err = same_side.GSS_VerifyMIC(data, token)
			assert err is not None
		else:
			res, conf, seq, err = receiver.GSS_Unwrap(token)
			assert err is None
			assert res == data
			assert conf is entry['conf']
			if conf is False and isinstance(receiver, GSSAPI_RFC4121):
				ours, err = same_side.GSS_Wrap(data, seq, confidential = False)
				assert err is None
				assert ours == token

			_, _, _, err = same_side.GSS_Unwrap(token)
			assert err is not None

@pytest.mark.parametrize('key', KEYS, ids = [str(k.enctype) for k in KEYS])
@pytest.mark.parametrize('acceptor_subkey', [True, False])
def test_roundtrip(key, acceptor_subkey):
	initiator = get_gssapi_rfc(key, is_initiator = True, acceptor_subkey = acceptor_subkey)
	acceptor = get_gssapi_rfc(key, is_initiator = False, acceptor_subkey = acceptor_subkey)
	seq_num = 0x12345678
	for sender, receiver in ((initiator, acceptor), (acceptor, initiator)):
		for data in DATA:
			token, err = sender.GSS_GetMIC(data, seq_num)
			assert err is None
			seq, err = receiver.GSS_VerifyMIC(data, token)
			assert err is None
			assert seq == seq_num

			for conf in (True, False):
				token, err = sender.GSS_Wrap(data, seq_num, confidential = conf)
				assert err is None
				res, res_conf, seq, err = receiver.GSS_Unwrap(token)
				assert err is None
				assert res == data
				assert res_conf is conf
				assert seq == seq_num
				if conf is True and len(data) > 8:
					assert data not in token
			seq_num += 1

@pytest.mark.parametrize('key', KEYS, ids = [str(k.enctype) for k in KEYS])
def test_tamper(key):
	initiator = get_gssapi_rfc(key, is_initiator = True)
	acceptor = get_gssapi_rfc(key, is_initiator = False)
	data = b'The quick brown fox jumps over the lazy dog'

	# RFC4757 tokens do not protect the sequence number itself (only the direction
	# after it), a changed one is for the sequence check of the context to catch
	skip = []
	if key.enctype == Enctype.RC4:
		skip = [21, 22, 23, 24]

	token, _ = initiator.GSS_GetMIC(data, 1)
	for i in range(len(token)):
		if i in skip:
			continue
		bad = token[:i] + bytes([token[i] ^ 1]) + token[i+1:]
		_, err = acceptor.GSS_VerifyMIC(data, bad)
		assert err is not None, 'MIC token byte %s' % i
	_, err = acceptor.GSS_VerifyMIC(data, token[:-1])
	assert err is not None

	for conf in (True, False):
		token, _ = initiator.GSS_Wrap(data, 1, confidential = conf)
		for i in range(len(token)):
			if i in skip and conf is False:
				continue
			bad = token[:i] + bytes([token[i] ^ 1]) + token[i+1:]
			res, _, _, err = acceptor.GSS_Unwrap(bad)
			assert err is not None, 'Wrap token byte %s conf %s' % (i, conf)
			assert res is None
		for i in range(len(token)):
			_, _, _, err = acceptor.GSS_Unwrap(token[:i])
			assert err is not None

	# wrong key
	other = get_gssapi_rfc(get_key(key.enctype, bytes(len(key.contents))), is_initiator = False)
	token, _ = initiator.GSS_GetMIC(data, 1)
	_, err = other.GSS_VerifyMIC(data, token)
	assert err is not None
	token, _ = initiator.GSS_Wrap(data, 1)
	_, _, _, err = other.GSS_Unwrap(token)
	assert err is not None

@pytest.mark.parametrize('key', KEYS[:2], ids = [str(k.enctype) for k in KEYS[:2]])
def test_cfx_token_layout(key):
	initiator = get_gssapi_rfc(key, is_initiator = True, acceptor_subkey = False)
	acceptor = get_gssapi_rfc(key, is_initiator = False, acceptor_subkey = True)
	data = b'0123456789'

	token, _ = initiator.GSS_GetMIC(data, 0x0102030405060708)
	assert token[:16] == bytes.fromhex('040400ffffffffff0102030405060708')
	assert len(token) == 16 + 12
	token, _ = acceptor.GSS_GetMIC(data, 1)
	assert token[:16] == bytes.fromhex('040405ffffffffff0000000000000001')

	# sign only: EC is the checksum size, the data is in clear
	token, _ = initiator.GSS_Wrap(data, 2, confidential = False)
	assert token[:16] == bytes.fromhex('050400ff000c00000000000000000002')
	assert token[16:16 + len(data)] == data
	assert len(token) == 16 + len(data) + 12
	# sealed: confounder + data + header + hmac
	token, _ = acceptor.GSS_Wrap(data, 3, confidential = True)
	assert token[:16] == bytes.fromhex('050407ff000000000000000000000003')
	assert len(token) == 16 + 16 + len(data) + 16 + 12

@pytest.mark.parametrize('key', KEYS[:2], ids = [str(k.enctype) for k in KEYS[:2]])
def test_cfx_rrc(key):
	# we always send RRC=0 but the peer is free to rotate (Windows does)
	initiator = get_gssapi_rfc(key, is_initiator = True)
	acceptor = get_gssapi_rfc(key, is_initiator = False)
	data = b'The quick brown fox jumps over the lazy dog'
	for conf in (True, False):
		token, _ = initiator.GSS_Wrap(data, 7, confidential = conf)
		body = token[16:]
		for rrc in (1, 12, 28, len(body) - 1, len(body), len(body) + 5):
			rotated = token[:6] + rrc.to_bytes(2, 'big') + token[8:16] + rotate_right(body, rrc)
			res, res_conf, seq, err = acceptor.GSS_Unwrap(rotated)
			assert err is None, 'rrc %s conf %s' % (rrc, conf)
			assert res == data
			assert res_conf is conf
		# RRC is not covered by the checksum but the rotation has to match it
		rotated = token[:6] + (5).to_bytes(2, 'big') + token[8:]
		_, _, _, err = acceptor.GSS_Unwrap(rotated)
		assert err is not None

def test_cfx_filler():
	# a peer may add filler bytes (EC) after the data in sealed tokens
	key = KEYS[0]
	acceptor = get_gssapi_rfc(key, is_initiator = False)
	data = b'0123456789'
	hdr = bytes.fromhex('050402ff000600000000000000000009')
	token = hdr + acceptor.cipher_type.encrypt(key, 24, data + b'\x00' * 6 + hdr, None)
	res, conf, seq, err = acceptor.GSS_Unwrap(token)
	assert err is None
	assert res == data
	assert seq == 9

def test_cfx_acceptor_subkey_flag():
	key = KEYS[0]
	initiator = get_gssapi_rfc(key, is_initiator = True, acceptor_subkey = True)
	acceptor = get_gssapi_rfc(key, is_initiator = False, acceptor_subkey = False)
	token, _ = initiator.GSS_GetMIC(b'data', 1)
	_, err = acceptor.GSS_VerifyMIC(b'data', token)
	assert err is not None
	token, _ = initiator.GSS_Wrap(b'data', 1)
	_, _, _, err = acceptor.GSS_Unwrap(token)
	assert err is not None

def test_framing():
	for size in (0, 1, 100, 117, 118, 119, 300, 70000):
		data = os.urandom(size)
		token = gss_frame(data)
		assert token[:1] == b'\x60'
		assert bytes.fromhex('06092a864886f712010202') in token[:16]
		assert gss_unframe(token) == data
	# RFC1964 1.1 example header: short form length, krb5 OID
	assert gss_frame(b'\x01\x00' + b'A' * 10) == bytes.fromhex('6017' + '06092a864886f712010202' + '0100') + b'A' * 10
	with pytest.raises(Exception):
		gss_unframe(b'\x61' + gss_frame(b'data')[1:])
	with pytest.raises(Exception):
		gss_unframe(gss_frame(b'data') + b'x')
	with pytest.raises(Exception):
		gss_unframe(gss_frame(b'A' * 200)[:-1])
	with pytest.raises(Exception):
		# SPNEGO oid
		gss_unframe(bytes.fromhex('600a06062b06010505020000'))

def test_unsupported_etype():
	with pytest.raises(Exception):
		get_gssapi_rfc(Key(Enctype.RC4_MD4, bytes(16)))
