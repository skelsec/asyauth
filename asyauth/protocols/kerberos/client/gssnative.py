
# Kerberos V5 GSSAPI mechanism (initiator) per RFC4121 / RFC1964, without SPNEGO
# and without the Windows specific behaviours of KerberosClientNative.
# Written for RPCSEC_GSS (NFS) against MIT krb5 / Heimdal based acceptors.
#
#	ctx = credential.build_gss_context() # credential is a KerberosCredential
#	token, to_continue, err = await ctx.authenticate(None, flags = flags, spn = 'nfs/server.test.corp@TEST.CORP')
#	# send token to the acceptor. If to_continue is set (mutual auth), feed its reply:
#	_, to_continue, err = await ctx.authenticate(reply_token)
#
#	mic, err = await ctx.get_mic(data)
#	_, err = await ctx.verify_mic(data, mic_from_peer)
#	token, err = await ctx.wrap(data, confidential = True)
#	data, confidential, err = await ctx.unwrap(token_from_peer)
#
# The per-message tokens follow the etype of the context key: AES (RFC4121), RC4
# (RFC4757), 3DES and DES (RFC1964). ctx.etypes is the list of ticket session key
# etypes the KDC is asked for, set it to get a weaker context than the default.
#
# Service in another realm: either the SPN has that realm or the KDC of the user
# knows and answers with a referral, both are followed. The KDC of the other realm
# is the cross_target of the credential (dcc, realmc). Without that, and for the
# realms in between when the trust is not a direct one, the name of the realm must
# resolve to its KDC as it does in AD.
#
# Sequence numbers are kept by the context. Incoming tokens are only checked for
# order / replay when GSS_C_SEQUENCE_FLAG / GSS_C_REPLAY_FLAG was requested, a
# protocol where messages arrive in any order (RPCSEC_GSS) must not request them.

import os
import datetime

from asyauth.protocols.kerberos import logger
from asyauth.common.credentials.kerberos import KerberosCredential
from asyauth.protocols.kerberos.gssapi import GSSAPIFlags
from asyauth.protocols.kerberos.gssapirfc import get_gssapi_rfc, gss_frame, gss_unframe, \
	TOK_ID_AP_REQ, TOK_ID_AP_REP, TOK_ID_ERROR

from unicrypto import hashlib
from minikerberos.common.spn import KerberosSPN
from minikerberos.gssapi.channelbindings import ChannelBindingsStruct
from minikerberos.protocol.asn1_structs import AP_REQ, AP_REP, EncAPRepPart, Ticket, \
	EncryptedData, KRB_ERROR, Authenticator, Checksum, APOptions, PrincipalName, \
	Realm, EncryptionKey, TGS_REP, krb5_pvno
from minikerberos.protocol.constants import MESSAGE_TYPE
from minikerberos.protocol.encryption import Key, Enctype, _enctype_table, _is_weak_des_key
from minikerberos.aioclient import AIOKerberosClient
from minikerberos.protocol.errors import KerberosError, KerberosErrorCode

# how many sequence numbers back a late token is still accepted
# when only replay detection is requested
REPLAY_WINDOW = 64

class StrictAIOKerberosClient(AIOKerberosClient):
	def tgs_from_ccache(self, spn_user:KerberosSPN):
		# The base class hands out the first service ticket of the ccache when
		# there is none for the SPN. An RFC conforming acceptor refuses a ticket
		# issued for another service, so only take exact matches here.
		try:
			if self.ccache is None:
				raise Exception('No CCACHE file found')
			tgs, keystruct, err = self.ccache.get_tgs(spn_user, strict = True)
			if err is not None:
				raise err
			key = Key(keystruct['keytype'], keystruct['keyvalue'])
			keydata = EncryptionKey({'keytype': keystruct['keytype'], 'keyvalue': keystruct['keyvalue']}).dump()
			tgs['enc-part'] = EncryptedData({'etype': 0, 'cipher': keydata})
			tgs = TGS_REP(tgs).native
			return tgs, tgs['enc-part'], key, None
		except Exception as e:
			return None, None, None, e

class KerberosGSSClientNative:
	def __init__(self, credential:KerberosCredential):
		self.credential = credential
		self.ccred = self.credential.to_ccred()

		self.kc = None
		self.session_key = None # ticket session key
		self.initiator_subkey = None
		self.acceptor_subkey = None
		self.context_key = None # the key protecting the per-message tokens
		self.gssapi = None
		self.iterations = 0
		self.established = False
		self.from_ccache = False

		# set this to False before authenticating to not send a subkey in the authenticator
		self.use_subkey = True
		# etypes of the ticket session key to ask the KDC for, in the order of preference.
		# The etype of the context follows this, set before authenticating (eg. [3] for DES only)
		self.etypes = [18, 17, 23, 16, 3]

		self.send_seq = 0
		self.recv_seq = 0
		self.recv_seq_seen = {}
		self.authenticator_ctime = None
		self.authenticator_cusec = None

		self.flags = \
			GSSAPIFlags.GSS_C_MUTUAL_FLAG |\
			GSSAPIFlags.GSS_C_CONF_FLAG |\
			GSSAPIFlags.GSS_C_INTEG_FLAG |\
			GSSAPIFlags.GSS_C_REPLAY_FLAG |\
			GSSAPIFlags.GSS_C_SEQUENCE_FLAG

	def is_established(self):
		return self.established

	def signing_needed(self):
		"""
		Checks if integrity protection was negotiated
		"""
		return GSSAPIFlags.GSS_C_INTEG_FLAG in self.flags

	def encryption_needed(self):
		"""
		Checks if confidentiality flag was negotiated
		"""
		return GSSAPIFlags.GSS_C_CONF_FLAG in self.flags

	def get_session_key(self):
		"""
		Returns the key of the established context (subkey if there is one)
		"""
		return self.context_key.contents

	def get_seq_number(self):
		"""
		Returns the sequence number the next outgoing token will have
		"""
		return self.send_seq

	async def get_mic(self, data:bytes):
		"""
		Creates a MIC token for data.
		"""
		try:
			self.check_established()
			token, err = self.gssapi.GSS_GetMIC(data, self.send_seq)
			if err is not None:
				raise err
			self.send_seq += 1
			return token, None
		except Exception as e:
			return None, e

	async def verify_mic(self, data:bytes, token:bytes):
		"""
		Verifies the MIC token the peer created for data.
		"""
		try:
			self.check_established()
			seq_num, err = self.gssapi.GSS_VerifyMIC(data, token)
			if err is not None:
				raise err
			self.check_recv_seq(seq_num)
			return True, None
		except Exception as e:
			return None, e

	async def wrap(self, data:bytes, confidential:bool = True):
		"""
		Creates a Wrap token carrying data. Encrypts data if confidential is set, otherwise integrity protection only.
		"""
		try:
			self.check_established()
			token, err = self.gssapi.GSS_Wrap(data, self.send_seq, confidential = confidential)
			if err is not None:
				raise err
			self.send_seq += 1
			return token, None
		except Exception as e:
			return None, e

	async def unwrap(self, token:bytes):
		"""
		Processes a Wrap token of the peer. Also performs integrity checking.
		Returns the data and wether the token was encrypted
		"""
		try:
			self.check_established()
			data, confidential, seq_num, err = self.gssapi.GSS_Unwrap(token)
			if err is not None:
				raise err
			self.check_recv_seq(seq_num)
			return data, confidential, None
		except Exception as e:
			return None, None, e

	def check_established(self):
		if self.established is False:
			raise Exception('Security context is not established')

	def check_recv_seq(self, seq_num:int):
		# only called on tokens which are already verified
		if GSSAPIFlags.GSS_C_SEQUENCE_FLAG in self.flags:
			if seq_num != self.recv_seq:
				raise Exception('Token out of sequence! Expected %s got %s' % (self.recv_seq, seq_num))
			self.recv_seq += 1
		elif GSSAPIFlags.GSS_C_REPLAY_FLAG in self.flags:
			if seq_num in self.recv_seq_seen:
				raise Exception('Duplicate token! Sequence number %s' % seq_num)
			if seq_num + REPLAY_WINDOW < self.recv_seq:
				raise Exception('Token too old! Sequence number %s' % seq_num)
			self.recv_seq_seen[seq_num] = 1
			if seq_num >= self.recv_seq:
				self.recv_seq = seq_num + 1
				for x in list(self.recv_seq_seen):
					if x + REPLAY_WINDOW < self.recv_seq:
						del self.recv_seq_seen[x]

	async def get_ticket(self, spn:KerberosSPN):
		# same logic as in KerberosClientNative
		try:
			#check TGS first, maybe ccache already has what we need
			tgs, encpart, session_key, err = self.kc.tgs_from_ccache(spn)
			if err:
				raise err
			logger.debug('Got TGS from CCACHE!')
			self.from_ccache = True
			return tgs, session_key
		except:
			pass

		try:
			await self.kc.get_TGT(override_etype = self.credential.etypes)
		except KerberosError as e:
			if e.errorcode != KerberosErrorCode.KDC_ERR_WRONG_REALM:
				logger.debug('Failed to get TGT! %s' % e)
				raise e
			# if the target user is in a different domain, we need to get a referral ticket
			newtarget = self.kc.target.get_kerberos_target(dc_ip=self.kc.credential.domain, domain=self.kc.credential.domain)
			newkc = AIOKerberosClient(self.ccred, newtarget)
			ref_tgs, ref_encpart, ref_key, new_factory = await newkc.get_referral_ticket(spn.domain, self.credential.target.get_ip_or_hostname())
			self.kc = new_factory.get_client()
			tgs, encpart, session_key = await self.kc.get_TGS(spn, override_etype = self.etypes)
			return tgs, session_key

		# if the target server is in a different domain, we need to get a referral ticket
		if self.credential.cross_target is not None and self.credential.cross_realm is not None:
			spn.domain = self.credential.cross_realm
		if self.credential.domain is not None and spn.domain.upper() != self.credential.domain.upper():
			await self.switch_realm(spn.domain)

		tgs, encpart, session_key = await self.kc.get_TGS(spn, override_etype = self.etypes)
		for _ in range(10):
			realm = self.get_referral_realm(tgs, spn)
			if realm is None:
				return tgs, session_key
			# the KDC did not give a ticket for the service but tells which realm to ask (RFC6806)
			logger.debug('Got referral to realm %s' % realm)
			await self.switch_realm(realm)
			spn.domain = realm
			tgs, encpart, session_key = await self.kc.get_TGS(spn, override_etype = self.etypes)
		raise Exception('Too many referrals')

	def get_referral_realm(self, tgs, spn:KerberosSPN):
		sname = tgs['ticket']['sname']['name-string']
		if len(sname) != 2 or sname[0].lower() != 'krbtgt':
			return None
		if spn.service is not None and spn.service.lower() == 'krbtgt':
			return None
		return sname[1]

	async def switch_realm(self, realm:str):
		# Continues with the KDC of the other realm. Its address is the cross_target of
		# the credential, without that the name of the realm has to resolve to the KDC.
		# The same goes for the realms in between when the trust is not a direct one.
		target_ip = None
		if self.credential.cross_target is not None:
			if self.credential.cross_realm is None or self.credential.cross_realm.upper() == realm.upper():
				target_ip = self.credential.cross_target.get_ip_or_hostname()
		ref_tgs, ref_encpart, ref_key, new_factory = await self.kc.get_referral_ticket(realm, target_ip)
		self.kc = new_factory.get_client()

	def generate_subkey(self):
		cipher = _enctype_table[self.session_key.enctype]
		if self.session_key.enctype != Enctype.DES_MD5:
			return cipher.random_to_key(os.urandom(cipher.seedsize))
		# MIT refuses DES keys with bad parity
		while True:
			keydata = b''
			for b in os.urandom(8):
				b &= 0xFE
				if bin(b).count('1') % 2 == 0:
					b |= 1
				keydata += bytes([b])
			if _is_weak_des_key(keydata) is False:
				return Key(self.session_key.enctype, keydata)

	def construct_apreq(self, tgs, cb_data:bytes = None):
		# RFC4121 4.1.1 authenticator checksum
		bnd = b'\x00' * 16
		if cb_data is not None:
			cb_struct = ChannelBindingsStruct()
			cb_struct.application_data = cb_data
			bnd = hashlib.md5(cb_struct.to_bytes()).digest()
		cksum  = len(bnd).to_bytes(4, byteorder = 'little', signed = False)
		cksum += bnd
		cksum += int(self.flags).to_bytes(4, byteorder = 'little', signed = False)

		now = datetime.datetime.now(datetime.timezone.utc)
		self.authenticator_cusec = now.microsecond
		self.authenticator_ctime = now.replace(microsecond=0)

		authenticator_data = {}
		authenticator_data['authenticator-vno'] = krb5_pvno
		authenticator_data['crealm'] = Realm(tgs['crealm'])
		authenticator_data['cname'] = PrincipalName(tgs['cname'])
		authenticator_data['cksum'] = Checksum({'cksumtype': 0x8003, 'checksum': cksum})
		authenticator_data['cusec'] = self.authenticator_cusec
		authenticator_data['ctime'] = self.authenticator_ctime
		if self.initiator_subkey is not None:
			authenticator_data['subkey'] = EncryptionKey({'keytype': self.initiator_subkey.enctype, 'keyvalue': self.initiator_subkey.contents})
		authenticator_data['seq-number'] = self.send_seq

		cipher = _enctype_table[self.session_key.enctype]
		authenticator_data_enc = cipher.encrypt(self.session_key, 11, Authenticator(authenticator_data).dump(), None)

		ap_opts = []
		if GSSAPIFlags.GSS_C_MUTUAL_FLAG in self.flags:
			ap_opts.append('mutual-required')

		ap_req = {}
		ap_req['pvno'] = krb5_pvno
		ap_req['msg-type'] = MESSAGE_TYPE.KRB_AP_REQ.value
		ap_req['ap-options'] = APOptions(set(ap_opts))
		ap_req['ticket'] = Ticket(tgs['ticket'])
		ap_req['authenticator'] = EncryptedData({'etype': self.session_key.enctype, 'cipher': authenticator_data_enc})
		return AP_REQ(ap_req).dump()

	def process_aprep(self, data:bytes):
		aprep = AP_REP.load(data).native
		if int(aprep['enc-part']['etype']) != self.session_key.enctype:
			raise Exception('AP_REP is encrypted with unexpected etype %s' % aprep['enc-part']['etype'])
		cipher = _enctype_table[self.session_key.enctype]
		temp = cipher.decrypt(self.session_key, 12, aprep['enc-part']['cipher'])
		enc_part = EncAPRepPart.load(temp).native
		logger.debug('EncAPRepPart: %s' % enc_part)

		# this is what proves the identity of the acceptor
		if enc_part['ctime'] != self.authenticator_ctime or enc_part['cusec'] != self.authenticator_cusec:
			raise Exception('Mutual authentication failed! AP_REP does not match the authenticator')

		if enc_part['subkey'] is not None:
			self.acceptor_subkey = Key(int(enc_part['subkey']['keytype']), enc_part['subkey']['keyvalue'])
		if enc_part['seq-number'] is not None:
			self.recv_seq = enc_part['seq-number']

	def setup_gssapi(self):
		if self.acceptor_subkey is not None:
			self.context_key = self.acceptor_subkey
		elif self.initiator_subkey is not None:
			self.context_key = self.initiator_subkey
		else:
			self.context_key = self.session_key
		self.gssapi = get_gssapi_rfc(self.context_key, is_initiator = True, acceptor_subkey = self.acceptor_subkey is not None)
		self.established = True

	async def authenticate(self, authData:bytes, flags:GSSAPIFlags = None, seq_number:int = None, cb_data:bytes = None, spn:str = None, **kwargs):
		"""
		This function is called (multiple times depending on the flags) to perform authentication.
		Returns the token to be sent to the acceptor (if any), wether the acceptor's reply token is expected, and the error

		flags: GSSAPIFlags to request. When mutual authentication is requested the context needs the reply token of the acceptor to be established.
		seq_number: initial sequence number, random if not set
		cb_data: application data for channel bindings
		spn: the service principal, like nfs/server.test.corp@TEST.CORP
		"""
		try:
			if self.iterations == 0:
				if flags is not None:
					self.flags = GSSAPIFlags(flags)
				if GSSAPIFlags.GSS_C_DCE_STYLE in self.flags:
					raise Exception('DCE style is not supported here, use the regular kerberos context')
				if GSSAPIFlags.GSS_C_DELEG_FLAG in self.flags:
					raise Exception('Delegation is not supported')
				logger.debug('Flags: %s' % self.flags)

				if spn is None:
					raise Exception("SPN is needed for kerberos!")
				if spn.find('@') == -1:
					spn = '%s@%s' % (spn, self.credential.domain)
				spn = KerberosSPN.from_spn(spn)
				logger.debug('SPN: %s' % spn)

				if self.kc is None:
					self.kc = StrictAIOKerberosClient(self.ccred, self.credential.target)

				tgs, self.session_key = await self.get_ticket(spn)

				if self.use_subkey is True:
					self.initiator_subkey = self.generate_subkey()

				self.send_seq = seq_number
				if self.send_seq is None:
					self.send_seq = int.from_bytes(os.urandom(4), 'big', signed = False) & 0x3fffffff
				# the acceptor starts with our sequence number unless the AP_REP tells otherwise
				self.recv_seq = self.send_seq

				apreq = self.construct_apreq(tgs, cb_data = cb_data)
				token = gss_frame(TOK_ID_AP_REQ + apreq)
				self.iterations += 1

				if GSSAPIFlags.GSS_C_MUTUAL_FLAG in self.flags:
					return token, True, None

				self.setup_gssapi()
				return token, False, None

			elif self.iterations == 1 and self.established is False:
				if not authData:
					raise Exception('Empty Kerberos response')

				data = gss_unframe(authData)
				token_id = data[:2]
				payload = data[2:]
				if token_id == TOK_ID_ERROR:
					raise KerberosError(KRB_ERROR.load(payload))
				if token_id != TOK_ID_AP_REP:
					raise Exception('Unexpected Kerberos GSS token ID: %s' % token_id.hex())

				self.process_aprep(payload)
				self.setup_gssapi()
				self.iterations += 1
				return None, False, None

			else:
				raise Exception('Security context is already established')

		except Exception as e:
			return None, None, e
