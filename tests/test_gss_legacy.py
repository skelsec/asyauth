# DES and 3DES (RFC1964 tokens) interop tests of the kerberos GSSAPI context
# against MIT krb5 1.17, the last release with single DES (see tests/lab/README.md)
import pytest

from asyauth.protocols.kerberos.gssapirfc import GSSAPI_RFC1964, GSSAPI_RFC4121, GSSAPI_RFC4757

from conftest import run
from test_gss_interop import establish, exchange, get_credential, BASE, MUTUAL, SEQ, ETYPES, DATA

@pytest.fixture
def peer(legacy):
	p = legacy.get_peer()
	yield p
	p.close()

@pytest.mark.parametrize('service', ['des3', 'des'])
@pytest.mark.parametrize('mutual', [True, False], ids = ['mutual', 'nomutual'])
@pytest.mark.parametrize('use_subkey', [True, False], ids = ['subkey', 'nosubkey'])
@pytest.mark.parametrize('seq', [True, False], ids = ['seq', 'noseq'])
def test_context(legacy, peer, service, mutual, use_subkey, seq):
	async def test():
		flags = BASE
		if mutual is True:
			flags |= MUTUAL
		if seq is True:
			flags |= SEQ
		ctx = await establish(legacy, peer, service = service, flags = flags, use_subkey = use_subkey)
		assert ctx.session_key.enctype == ETYPES[service]
		assert isinstance(ctx.gssapi, GSSAPI_RFC1964)
		# no key of its own from the acceptor with these, MIT sends back ours in the AP_REP
		if use_subkey is True:
			assert ctx.get_session_key() == ctx.initiator_subkey.contents
		else:
			assert ctx.get_session_key() == ctx.session_key.contents
		for _ in range(2):
			for data in DATA:
				await exchange(ctx, peer, data)
	run(test())

@pytest.mark.parametrize('service', ['des3', 'des'])
def test_sequence(legacy, peer, service):
	async def test():
		ctx = await establish(legacy, peer, service = service, flags = BASE | MUTUAL | SEQ)
		res = peer.call(cmd = 'get_mic', data = b'first')
		first = bytes.fromhex(res['token'])
		res = peer.call(cmd = 'get_mic', data = b'second')
		_, err = await ctx.verify_mic(b'second', bytes.fromhex(res['token']))
		assert err is not None
		_, err = await ctx.verify_mic(b'first', first)
		assert err is None
		_, err = await ctx.verify_mic(b'first', first)
		assert err is not None

		# the peer does the same with ours
		token, _ = await ctx.get_mic(b'a')
		peer.call(cmd = 'verify_mic', data = b'a', token = token)
		assert 'error' in peer.call_raw(cmd = 'verify_mic', data = b'a', token = token)
	run(test())

@pytest.mark.parametrize('etypes, gssapi', [(None, GSSAPI_RFC4121), ([18], GSSAPI_RFC4121), ([23], GSSAPI_RFC4757), ([16], GSSAPI_RFC1964), ([3], GSSAPI_RFC1964), ([3, 16, 18], GSSAPI_RFC1964)], ids = str)
def test_etype_choice(legacy, peer, etypes, gssapi):
	# the service has keys of all etypes, the client decides how weak the context gets
	async def test():
		ctx = await establish(legacy, peer, service = 'any', etypes = etypes)
		assert ctx.session_key.enctype == (etypes[0] if etypes is not None else 18)
		assert isinstance(ctx.gssapi, gssapi)
		await exchange(ctx, peer, b'etypes')
	run(test())

@pytest.mark.parametrize('service', ['aes256', 'aes128', 'rc4'])
def test_old_mit(legacy, peer, service):
	# the other token types against the old release
	async def test():
		ctx = await establish(legacy, peer, service = service)
		assert ctx.session_key.enctype == ETYPES[service]
		for data in DATA:
			await exchange(ctx, peer, data)
	run(test())

@pytest.mark.parametrize('etypes', [None, [1]], ids = str)
def test_des_cbc_crc(legacy, etypes):
	# minikerberos has no des-cbc-crc, a context with such a session key can not be established
	async def test():
		ctx = get_credential(legacy).build_gss_context()
		if etypes is not None:
			ctx.etypes = etypes
		token, _, err = await ctx.authenticate(None, spn = 'nfs/descrc.legacy.lab')
		assert err is not None
		assert token is None
	run(test())
