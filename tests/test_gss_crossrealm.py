# Cross-realm tests of the RFC4121 kerberos GSSAPI context against MIT krb5.
# Three realms: the user is in TEST.LAB which is trusted by OTHER.LAB which is
# trusted by THIRD.LAB (see tests/lab/README.md)
import pytest

from asysocks.unicomm.common.target import UniTarget, UniProto

from asyauth.common.constants import asyauthSecret
from asyauth.common.credentials.kerberos import KerberosCredential

from conftest import run
from test_gss_interop import establish as establish_ctx, exchange, BASE, MUTUAL, ETYPES

def get_cross_credential(lab, cross = None, cross_realm = True, stype = asyauthSecret.PASSWORD, secret = None):
	"""Credential of the user in lab, cross is the realm of the service if the address of its KDC is to be given"""
	target = UniTarget(lab.ip, 88, UniProto.CLIENT_TCP, dc_ip = lab.ip, domain = lab.realm)
	cross_target = None
	if cross is not None:
		cross_target = UniTarget(cross.ip, 88, UniProto.CLIENT_TCP, dc_ip = cross.ip)
	if secret is None:
		secret = lab.password
	return KerberosCredential(secret, lab.user, lab.realm, stype, target = target, cross_target = cross_target, cross_realm = cross.realm if cross is not None and cross_realm is True else None)

async def establish(lab, service_lab, credential, spn = None, service = 'aes256', flags = BASE | MUTUAL):
	if spn is None:
		spn = 'nfs/%s.%s@%s' % (service, service_lab.domain, service_lab.realm)
	peer = service_lab.get_peer()
	try:
		ctx = await establish_ctx(lab, peer, flags = flags, credential = credential, spn = spn)
		assert ctx.session_key.enctype == ETYPES[service]
		await exchange(ctx, peer, b'cross-realm')
		return ctx
	finally:
		peer.close()

@pytest.mark.parametrize('service', ['aes256', 'aes128', 'rc4'])
@pytest.mark.parametrize('mutual', [True, False], ids = ['mutual', 'nomutual'])
def test_cross_target(lab, xlabs, service, mutual):
	# address and name of the other realm are given in the credential, no name resolution
	async def test():
		other = xlabs['OTHER.LAB']
		flags = BASE | MUTUAL if mutual is True else BASE
		await establish(lab, other, get_cross_credential(lab, other), service = service, flags = flags)
	run(test())

def test_cross_target_spn_without_realm(lab, xlabs):
	# realm of the service comes from the credential
	async def test():
		other = xlabs['OTHER.LAB']
		await establish(lab, other, get_cross_credential(lab, other), spn = 'nfs/aes256.other.lab')
	run(test())

def test_cross_target_without_cross_realm(lab, xlabs):
	# realm of the service comes from the SPN
	async def test():
		other = xlabs['OTHER.LAB']
		await establish(lab, other, get_cross_credential(lab, other, cross_realm = False))
	run(test())

def test_spn_realm(lab, xlabs, realm_dns):
	# nothing but the realm in the SPN tells that the service is in another realm
	async def test():
		await establish(lab, xlabs['OTHER.LAB'], get_cross_credential(lab))
	run(test())

def test_spn_realm_not_resolving(lab, xlabs):
	async def test():
		ctx = get_cross_credential(lab).build_gss_context()
		_, _, err = await ctx.authenticate(None, spn = 'nfs/aes256.other.lab@OTHER.LAB')
		assert err is not None
		assert ctx.is_established() is False
	run(test())

def test_transitive_cross_target(lab, xlabs, realm_dns):
	# no direct trust between the realms of the user and of the service. The KDC of the
	# realm in between is found by name
	async def test():
		third = xlabs['THIRD.LAB']
		await establish(lab, third, get_cross_credential(lab, third))
	run(test())

def test_transitive_spn_realm(lab, xlabs, realm_dns):
	async def test():
		await establish(lab, xlabs['THIRD.LAB'], get_cross_credential(lab))
	run(test())

@pytest.mark.parametrize('spn', ['nfs/aes256.other.lab', 'nfs/aes256.other.lab@TEST.LAB'])
def test_kdc_referral(lab, xlabs, realm_dns, spn):
	# the client does not know that the service is in another realm, the KDC
	# answers with a referral instead of the service ticket
	async def test():
		await establish(lab, xlabs['OTHER.LAB'], get_cross_credential(lab), spn = spn)
	run(test())

def test_kdc_referral_cross_target(lab, xlabs):
	async def test():
		other = xlabs['OTHER.LAB']
		await establish(lab, other, get_cross_credential(lab, other, cross_realm = False), spn = 'nfs/aes256.other.lab@TEST.LAB')
	run(test())

def test_kdc_referral_transitive(lab, xlabs, realm_dns):
	# one referral from each KDC on the way
	async def test():
		await establish(lab, xlabs['THIRD.LAB'], get_cross_credential(lab), spn = 'nfs/aes256.third.lab')
	run(test())

def test_kdc_referral_not_resolving(lab, xlabs):
	# a referral must never be used as the service ticket
	async def test():
		ctx = get_cross_credential(lab).build_gss_context()
		token, _, err = await ctx.authenticate(None, spn = 'nfs/aes256.other.lab')
		assert err is not None
		assert token is None
	run(test())

def test_credential_ccache(lab, xlabs, tmp_path):
	# ccache made by the MIT client, has the tickets of the whole path to the service
	# in THIRD.LAB but none for the one in OTHER.LAB
	async def test():
		config = '[libdefaults]\n\tdefault_realm = TEST.LAB\n\tdns_lookup_kdc = false\n[realms]\n'
		for realm in xlabs:
			config += '\t%s = {\n\t\tkdc = %s\n\t}\n' % (realm, xlabs[realm].ip)
		config += '[capaths]\n\tTEST.LAB = {\n\t\tOTHER.LAB = .\n\t\tTHIRD.LAB = OTHER.LAB\n\t}\n'
		lab.run('cat > /tmp/cross.conf <<EOF\n%sEOF\n' % config +
			'rm -f /tmp/cross.ccache\n' +
			'kinit -k -t /creds/alice.keytab -c /tmp/cross.ccache alice\n' +
			'kvno -c /tmp/cross.ccache nfs/aes256.third.lab@THIRD.LAB\n', env = {'KRB5_CONFIG' : '/tmp/cross.conf'})
		ccache = tmp_path / 'cross.ccache'

		# service ticket from the ccache, a KDC which does not exist must not matter
		ccache.write_bytes(lab.read_file('/tmp/cross.ccache'))
		credential = get_cross_credential(lab, stype = asyauthSecret.CCACHE, secret = str(ccache))
		credential.target = UniTarget('192.0.2.1', 88, UniProto.CLIENT_TCP, dc_ip = '192.0.2.1', domain = lab.realm, timeout = 2)
		ctx = await establish(lab, xlabs['THIRD.LAB'], credential)
		assert ctx.from_ccache is True

		# only the TGT is of use here
		ccache.write_bytes(lab.read_file('/tmp/cross.ccache'))
		other = xlabs['OTHER.LAB']
		ctx = await establish(lab, other, get_cross_credential(lab, other, stype = asyauthSecret.CCACHE, secret = str(ccache)))
		assert ctx.from_ccache is False
	run(test())

def test_no_trust(lab, xlabs):
	# trusts are one way
	async def test():
		third = xlabs['THIRD.LAB']
		ctx = get_cross_credential(third, lab).build_gss_context()
		token, _, err = await ctx.authenticate(None, spn = 'nfs/aes256.test.lab@TEST.LAB')
		assert err is not None
		assert token is None
	run(test())

def test_same_realm_untouched(lab, xlabs, peer):
	# cross-realm settings of the credential do not disturb when the service is in the realm of the user
	async def test():
		ctx = await establish_ctx(lab, peer, credential = get_cross_credential(lab, xlabs['OTHER.LAB'], cross_realm = False))
		await exchange(ctx, peer, b'home')
	run(test())
