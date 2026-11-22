#!/usr/bin/env python3
# Generates per-message token test vectors with MIT krb5 on both sides of the context.
# Run inside the lab container, prints JSON. See tests/test_gssapirfc.py
import os
import sys
import json
import gssapi
from gssapi.raw import inquire_sec_context_by_oid, OID

INQ_SESSION_KEY = OID.from_int_seq('1.2.840.113554.1.2.2.5.5')
F = gssapi.RequirementFlag
DATA = [b'', b'a', b'0123456789abcdef', b'The quick brown fox jumps over the lazy dog']

def gen(user, service, enctype, mutual):
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
		'user' : user, 'service' : service, 'enctype' : enctype, 'acceptor_subkey' : mutual,
		'key' : key[0].hex(),
		'initiator' : [], 'acceptor' : [],
	}
	for name, ctx in (('initiator', ictx), ('acceptor', actx)):
		for data in DATA:
			res[name].append({'type' : 'mic', 'data' : data.hex(), 'token' : ctx.get_signature(data).hex()})
			res[name].append({'type' : 'wrap', 'conf' : False, 'data' : data.hex(), 'token' : ctx.wrap(data, False).message.hex()})
			res[name].append({'type' : 'wrap', 'conf' : True, 'data' : data.hex(), 'token' : ctx.wrap(data, True).message.hex()})
	return res

domain = os.environ.get('LAB_REALM', 'TEST.LAB').lower()
services = {'aes256' : 18, 'aes128' : 17, 'rc4' : 23}
if os.environ.get('LAB_LEGACY'):
	services = {'des3' : 16, 'des' : 3, 'descrc' : 1}

vectors = []
for service in services:
	for mutual in (True, False):
		if mutual is True and services[service] not in (17, 18):
			# MIT initiators offer their enctypes (RFC4537) and the acceptor answers with
			# an AES subkey, that would be the same tokens as with the AES services
			continue
		vectors.append(gen('alice', 'nfs/%s.%s' % (service, domain), services[service], mutual))
json.dump(vectors, sys.stdout, indent = 1)
