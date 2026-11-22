#!/usr/bin/env python3
# Generates per-message token test vectors with MIT krb5 on both sides of the context.
# Run inside the lab container, prints JSON. See tests/test_gssapirfc_vectors.py
import os
import sys
import json
import gssapi
from gssapi.raw import inquire_sec_context_by_oid, OID

INQ_SESSION_KEY = OID.from_int_seq('1.2.840.113554.1.2.2.5.5')
F = gssapi.RequirementFlag
DATA = [b'', b'a', b'0123456789abcdef', b'The quick brown fox jumps over the lazy dog']

def gen(user, service, mutual):
	os.environ['KRB5CCNAME'] = 'MEMORY:%s' % user
	icreds = gssapi.raw.acquire_cred_from({b'client_keytab' : b'/creds/alice.keytab', b'ccache' : b'MEMORY:%s' % user.encode()}, name = gssapi.Name(user, gssapi.NameType.kerberos_principal), usage = 'initiate').creds
	flags = [F.integrity, F.confidentiality]
	if mutual:
		flags.append(F.mutual_authentication)
	ictx = gssapi.SecurityContext(name = gssapi.Name(service, gssapi.NameType.kerberos_principal), creds = gssapi.Credentials(icreds), usage = 'initiate', flags = flags)
	actx = gssapi.SecurityContext(creds = gssapi.Credentials(usage = 'accept'), usage = 'accept')
	token = None
	while not (ictx.complete and actx.complete):
		token = ictx.step(token)
		if token:
			token = actx.step(token)
	key = inquire_sec_context_by_oid(ictx, INQ_SESSION_KEY)
	res = {
		'user' : user, 'service' : service, 'acceptor_subkey' : mutual,
		'key' : key[0].hex(),
		'initiator' : [], 'acceptor' : [],
	}
	for name, ctx in (('initiator', ictx), ('acceptor', actx)):
		for data in DATA:
			res[name].append({'type' : 'mic', 'data' : data.hex(), 'token' : ctx.get_signature(data).hex()})
			res[name].append({'type' : 'wrap', 'conf' : False, 'data' : data.hex(), 'token' : ctx.wrap(data, False).message.hex()})
			res[name].append({'type' : 'wrap', 'conf' : True, 'data' : data.hex(), 'token' : ctx.wrap(data, True).message.hex()})
	return res

vectors = []
for user, service in (('alice', 'nfs/aes256.test.lab'), ('alice', 'nfs/aes128.test.lab'), ('alice', 'nfs/rc4.test.lab')):
	for mutual in (True, False):
		vectors.append(gen(user, service, mutual))
json.dump(vectors, sys.stdout, indent = 1)
