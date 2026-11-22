# Interop tests of the RFC4121 kerberos GSSAPI context against MIT krb5
# (KDC + MIT GSSAPI acceptor in docker, see tests/lab/README.md)
import os
import datetime

import pytest

from asysocks.unicomm.common.target import UniTarget, UniProto
from minikerberos.protocol.asn1_structs import KRB_ERROR
from minikerberos.protocol.errors import KerberosError

from asyauth.common.constants import asyauthSecret
from asyauth.common.credentials.kerberos import KerberosCredential
from asyauth.protocols.kerberos.gssapi import GSSAPIFlags
from asyauth.protocols.kerberos.gssapirfc import gss_frame, gss_unframe, GSSAPI_RFC4121, GSSAPI_RFC4757

from conftest import run

F = GSSAPIFlags
BASE = F.GSS_C_CONF_FLAG | F.GSS_C_INTEG_FLAG
SEQ = F.GSS_C_REPLAY_FLAG | F.GSS_C_SEQUENCE_FLAG
MUTUAL = F.GSS_C_MUTUAL_FLAG

ETYPES = {'aes256' : 18, 'aes128' : 17, 'rc4' : 23, 'des3' : 16, 'des' : 3}
DATA = [b'', b'a', b'0123456789abcdef', b'The quick brown fox jumps over the lazy dog', os.urandom(5000)]

def get_credential(lab, stype = asyauthSecret.PASSWORD, secret = None):
	target = UniTarget(lab.ip, 88, UniProto.CLIENT_TCP, dc_ip = lab.ip, domain = lab.realm)
	if secret is None:
		secret = lab.password
	return KerberosCredential(secret, lab.user, lab.realm, stype, target = target)

async def establish(lab, peer, service = 'aes256', flags = BASE | MUTUAL, use_subkey = True, cb_data = None, peer_cb = None, credential = None, spn = None, etypes = None):
	if spn is None:
		spn = 'nfs/%s.%s@%s' % (service, lab.domain, lab.realm)
	if credential is None:
		credential = get_credential(lab)
	ctx = credential.build_gss_context()
	ctx.use_subkey = use_subkey
	if etypes is not None:
		ctx.etypes = etypes
	token, to_continue, err = await ctx.authenticate(None, flags = flags, spn = spn, cb_data = cb_data)
	if err is not None:
		raise err
	assert gss_unframe(token)[:2] == b'\x01\x00'
	assert to_continue is (MUTUAL in flags)
	assert ctx.is_established() is not to_continue

	res = peer.call(cmd = 'accept', token = token, cb = peer_cb)
	assert res['complete'] is True
	assert res['initiator'] == '%s@%s' % (lab.user, lab.realm)
	if to_continue is True:
		_, to_continue, err = await ctx.authenticate(bytes.fromhex(res['token']))
		if err is not None:
			raise err
		assert to_continue is False
	else:
		assert res['token'] is None
	assert ctx.is_established() is True
	# both sides have to end up with the same key and flags
	assert ctx.get_session_key().hex() == res['key']
	for flag in (F.GSS_C_MUTUAL_FLAG, F.GSS_C_REPLAY_FLAG, F.GSS_C_SEQUENCE_FLAG, F.GSS_C_CONF_FLAG, F.GSS_C_INTEG_FLAG):
		assert (flag in flags) == bool(res['flags'] & flag), flag
	return ctx

async def exchange(ctx, peer, data):
	"""All per-message token types in both directions"""
	token, err = await ctx.get_mic(data)
	assert err is None
	peer.call(cmd = 'verify_mic', data = data, token = token)
	assert 'error' in peer.call_raw(cmd = 'verify_mic', data = data + b'x', token = token)

	res = peer.call(cmd = 'get_mic', data = data)
	_, err = await ctx.verify_mic(data + b'x', bytes.fromhex(res['token']))
	assert err is not None
	ok, err = await ctx.verify_mic(data, bytes.fromhex(res['token']))
	assert err is None
	assert ok is True

	for conf in (False, True):
		token, err = await ctx.wrap(data, confidential = conf)
		assert err is None
		res = peer.call(cmd = 'unwrap', token = token)
		assert bytes.fromhex(res['data']) == data
		assert res['conf'] is conf

		res = peer.call(cmd = 'wrap', data = data, conf = conf)
		assert res['conf'] is conf
		res_data, res_conf, err = await ctx.unwrap(bytes.fromhex(res['token']))
		assert err is None
		assert res_data == data
		assert res_conf is conf

@pytest.mark.parametrize('service', ['aes256', 'aes128', 'rc4'])
@pytest.mark.parametrize('mutual', [True, False], ids = ['mutual', 'nomutual'])
@pytest.mark.parametrize('use_subkey', [True, False], ids = ['subkey', 'nosubkey'])
@pytest.mark.parametrize('seq', [True, False], ids = ['seq', 'noseq'])
def test_context(lab, peer, service, mutual, use_subkey, seq):
	async def test():
		flags = BASE
		if mutual is True:
			flags |= MUTUAL
		if seq is True:
			flags |= SEQ
		ctx = await establish(lab, peer, service = service, flags = flags, use_subkey = use_subkey)
		assert ctx.session_key.enctype == ETYPES[service]
		if service == 'rc4':
			assert isinstance(ctx.gssapi, GSSAPI_RFC4757)
		else:
			assert isinstance(ctx.gssapi, GSSAPI_RFC4121)
			# MIT always asserts a subkey in the AP_REP for these
			assert ctx.gssapi.acceptor_subkey is mutual
			assert (ctx.acceptor_subkey is not None) is mutual
		if mutual is False:
			if use_subkey is True:
				assert ctx.get_session_key() == ctx.initiator_subkey.contents
			else:
				assert ctx.get_session_key() == ctx.session_key.contents
		for _ in range(2):
			for data in DATA:
				await exchange(ctx, peer, data)
	run(test())

@pytest.mark.parametrize('service', ['aes256', 'rc4'])
def test_sequence(lab, peer, service):
	async def test():
		ctx = await establish(lab, peer, service = service, flags = BASE | MUTUAL | SEQ)
		data = b'sequence'
		await exchange(ctx, peer, data)

		# replayed tokens are refused by both sides
		token, err = await ctx.get_mic(data)
		assert err is None
		peer.call(cmd = 'verify_mic', data = data, token = token)
		assert 'error' in peer.call_raw(cmd = 'verify_mic', data = data, token = token)

		res = peer.call(cmd = 'wrap', data = data, conf = True)
		_, _, err = await ctx.unwrap(bytes.fromhex(res['token']))
		assert err is None
		_, _, err = await ctx.unwrap(bytes.fromhex(res['token']))
		assert err is not None

		# a skipped token
		peer.call(cmd = 'get_mic', data = data)
		res = peer.call(cmd = 'get_mic', data = data)
		_, err = await ctx.verify_mic(data, bytes.fromhex(res['token']))
		assert err is not None
	run(test())

@pytest.mark.parametrize('service', ['aes256', 'rc4'])
def test_replay_only(lab, peer, service):
	async def test():
		ctx = await establish(lab, peer, service = service, flags = BASE | MUTUAL | F.GSS_C_REPLAY_FLAG)
		data = b'replay'
		# out of order is fine, duplicates are not
		tokens = [bytes.fromhex(peer.call(cmd = 'get_mic', data = data)['token']) for _ in range(4)]
		for i in (2, 0, 3, 1):
			_, err = await ctx.verify_mic(data, tokens[i])
			assert err is None
		for i in range(4):
			_, err = await ctx.verify_mic(data, tokens[i])
			assert err is not None

		ours = [(await ctx.get_mic(data))[0] for _ in range(3)]
		for i in (1, 0, 2):
			peer.call(cmd = 'verify_mic', data = data, token = ours[i])
		assert 'error' in peer.call_raw(cmd = 'verify_mic', data = data, token = ours[1])
	run(test())

def test_no_sequence_flags(lab, peer):
	# what RPCSEC_GSS needs: replies arrive in any order, the RPC layer has its own sequence numbers
	async def test():
		ctx = await establish(lab, peer, flags = BASE | MUTUAL)
		data = b'unordered'
		tokens = [bytes.fromhex(peer.call(cmd = 'wrap', data = data, conf = True)['token']) for _ in range(3)]
		for i in (2, 0, 1, 1):
			res, _, err = await ctx.unwrap(tokens[i])
			assert err is None
			assert res == data
	run(test())

def test_channel_bindings(lab):
	async def test():
		cb_data = b'tls-server-end-point:' + os.urandom(32)
		peer = lab.get_peer()
		ctx = await establish(lab, peer, cb_data = cb_data, peer_cb = cb_data)
		await exchange(ctx, peer, b'bound')
		peer.close()

		peer = lab.get_peer()
		with pytest.raises(Exception, match = 'MIT peer error'):
			await establish(lab, peer, cb_data = cb_data, peer_cb = b'something else')
		peer.close()
	run(test())

def test_credential_keytab(lab, peer, tmp_path):
	async def test():
		keytab = tmp_path / 'alice.keytab'
		keytab.write_bytes(lab.read_file('/creds/alice.keytab'))
		ctx = await establish(lab, peer, credential = get_credential(lab, asyauthSecret.KEYTAB, str(keytab)))
		assert ctx.from_ccache is False
		await exchange(ctx, peer, b'keytab')
	run(test())

@pytest.mark.parametrize('service', ['aes256', 'aes128'])
def test_credential_ccache(lab, peer, tmp_path, service):
	# the ccache has the TGT and the ticket for the aes256 service
	async def test():
		ccache = tmp_path / 'alice.ccache'
		ccache.write_bytes(lab.read_file('/creds/alice.ccache'))
		ctx = await establish(lab, peer, service = service, credential = get_credential(lab, asyauthSecret.CCACHE, str(ccache)))
		assert ctx.from_ccache is (service == 'aes256')
		await exchange(ctx, peer, b'ccache')
	run(test())

def test_spn_without_realm(lab, peer):
	async def test():
		ctx = get_credential(lab).build_gss_context()
		token, to_continue, err = await ctx.authenticate(None, spn = 'nfs/aes256.test.lab')
		assert err is None
		res = peer.call(cmd = 'accept', token = token)
		_, _, err = await ctx.authenticate(bytes.fromhex(res['token']))
		assert err is None
		# default flags
		assert ctx.flags == BASE | MUTUAL | SEQ
		await exchange(ctx, peer, b'default')
	run(test())

def test_wrong_password(lab):
	async def test():
		ctx = get_credential(lab, secret = 'wrong').build_gss_context()
		token, to_continue, err = await ctx.authenticate(None, spn = 'nfs/aes256.test.lab')
		assert token is None
		# MIT does not ask for preauth by default, the AS_REP fails to decrypt
		assert err is not None
	run(test())

def test_unknown_service(lab):
	async def test():
		ctx = get_credential(lab).build_gss_context()
		token, to_continue, err = await ctx.authenticate(None, spn = 'nfs/nothere.test.lab')
		assert token is None
		assert isinstance(err, KerberosError)
	run(test())

def test_unsupported_flags(lab):
	async def test():
		for flag in (F.GSS_C_DCE_STYLE, F.GSS_C_DELEG_FLAG):
			ctx = get_credential(lab).build_gss_context()
			token, to_continue, err = await ctx.authenticate(None, flags = BASE | flag, spn = 'nfs/aes256.test.lab')
			assert token is None
			assert err is not None
	run(test())

def test_not_established(lab, peer):
	async def test():
		ctx = get_credential(lab).build_gss_context()
		_, err = await ctx.get_mic(b'data')
		assert err is not None
		token, to_continue, err = await ctx.authenticate(None, flags = BASE | MUTUAL, spn = 'nfs/aes256.test.lab')
		assert err is None
		# mutual auth is pending, nothing may be protected with the keys yet
		_, err = await ctx.get_mic(b'data')
		assert err is not None
		_, err = await ctx.wrap(b'data')
		assert err is not None
		_, _, err = await ctx.unwrap(b'data')
		assert err is not None
		_, err = await ctx.verify_mic(b'data', b'data')
		assert err is not None
	run(test())

def test_bad_acceptor_reply(lab, tmp_path):
	async def test():
		# both contexts use the same ticket, so the AP_REP of one decrypts in the other
		ccache = tmp_path / 'alice.ccache'
		ccache.write_bytes(lab.read_file('/creds/alice.ccache'))
		replies = []
		contexts = []
		for _ in range(2):
			peer = lab.get_peer()
			ctx = get_credential(lab, asyauthSecret.CCACHE, str(ccache)).build_gss_context()
			token, _, err = await ctx.authenticate(None, flags = BASE | MUTUAL, spn = 'nfs/aes256.test.lab')
			assert err is None
			replies.append(bytes.fromhex(peer.call(cmd = 'accept', token = token)['token']))
			contexts.append(ctx)
			peer.close()
		assert contexts[0].session_key.contents == contexts[1].session_key.contents

		# AP_REP for another authenticator
		_, _, err = await contexts[0].authenticate(replies[1])
		assert err is not None
		assert 'Mutual authentication failed' in str(err)
		assert contexts[0].is_established() is False

		# garbage
		for reply in (b'', b'garbage', replies[0][:-1], replies[0][:-5] + bytes(5), gss_frame(b'\x04\x04' + gss_unframe(replies[0])[2:])):
			_, _, err = await contexts[0].authenticate(reply)
			assert err is not None
			assert contexts[0].is_established() is False

		# the correct one still works after the failed attempts
		_, to_continue, err = await contexts[0].authenticate(replies[0])
		assert err is None
		assert to_continue is False
		assert contexts[0].is_established() is True
		_, _, err = await contexts[0].authenticate(replies[0])
		assert err is not None
	run(test())

def test_error_token(lab):
	async def test():
		ctx = get_credential(lab).build_gss_context()
		token, _, err = await ctx.authenticate(None, flags = BASE | MUTUAL, spn = 'nfs/aes256.test.lab')
		assert err is None
		now = datetime.datetime.now(datetime.timezone.utc)
		krb_error = KRB_ERROR({
			'pvno' : 5,
			'msg-type' : 30,
			'stime' : now.replace(microsecond = 0),
			'susec' : 0,
			'error-code' : 37, #KRB_AP_ERR_SKEW
			'realm' : lab.realm,
			'sname' : {'name-type' : 2, 'name-string' : ['nfs', 'aes256.test.lab']},
		}).dump()
		_, _, err = await ctx.authenticate(gss_frame(b'\x03\x00' + krb_error))
		assert isinstance(err, KerberosError)
		assert ctx.is_established() is False
	run(test())
