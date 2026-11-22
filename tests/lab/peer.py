#!/usr/bin/env python3
# MIT krb5 GSSAPI acceptor driven over stdin/stdout, one JSON object per line.
# Byte fields are hex encoded. One process is one security context.
import sys
import json
import gssapi
from gssapi.raw import ChannelBindings, inquire_sec_context_by_oid, OID

# GSS_KRB5_INQ_SSPI_SESSION_KEY
INQ_SESSION_KEY = OID.from_int_seq('1.2.840.113554.1.2.2.5.5')

ctx = None

def handle(req):
	global ctx
	cmd = req['cmd']
	if cmd == 'accept':
		if ctx is None:
			cb = None
			if req.get('cb') is not None:
				cb = ChannelBindings(application_data = bytes.fromhex(req['cb']))
			ctx = gssapi.SecurityContext(creds = gssapi.Credentials(usage = 'accept'), usage = 'accept', channel_bindings = cb)
		token = ctx.step(bytes.fromhex(req['token']))
		res = {'token' : token.hex() if token else None, 'complete' : ctx.complete}
		if ctx.complete:
			res['flags'] = int(ctx.actual_flags)
			res['initiator'] = str(ctx.initiator_name)
			res['key'] = inquire_sec_context_by_oid(ctx, INQ_SESSION_KEY)[0].hex()
		return res
	if cmd == 'get_mic':
		return {'token' : ctx.get_signature(bytes.fromhex(req['data'])).hex()}
	if cmd == 'verify_mic':
		ctx.verify_signature(bytes.fromhex(req['data']), bytes.fromhex(req['token']))
		return {}
	if cmd == 'wrap':
		res = ctx.wrap(bytes.fromhex(req['data']), req['conf'])
		return {'token' : res.message.hex(), 'conf' : res.encrypted}
	if cmd == 'unwrap':
		res = ctx.unwrap(bytes.fromhex(req['token']))
		return {'data' : res.message.hex(), 'conf' : res.encrypted}
	raise Exception('Unknown command %s' % cmd)

for line in sys.stdin:
	line = line.strip()
	if not line:
		continue
	try:
		res = handle(json.loads(line))
	except Exception as e:
		res = {'error' : '%s: %s' % (type(e).__name__, e)}
	sys.stdout.write(json.dumps(res) + '\n')
	sys.stdout.flush()
