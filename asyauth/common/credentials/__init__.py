import base64
import platform
import copy
from urllib.parse import urlparse, parse_qs, unquote
from asyauth.utils.paramprocessor import str_one, int_one, bool_one
from asyauth.common.constants import asyauthSecret, asyauthProtocol, asyauthSubProtocol
from asyauth.common.subprotocols import SubProtocol, SubProtocolNative, SubProtocolSSPI


class UniCredential:
	def __init__(self, secret:str = None, username:str = None, domain:str = None, stype:asyauthSecret = asyauthSecret.NONE, protocol:asyauthProtocol = None, subprotocol:SubProtocol = SubProtocolNative(), **kwargs):
		self.domain = domain
		self.username = username
		self.secret = secret
		self.stype = stype
		self.protocol = protocol
		self.subprotocol = subprotocol
		self.metadata = kwargs

		if stype in [asyauthSecret.PASS, asyauthSecret.PW]:
			self.stype = asyauthSecret.PASSWORD
		elif stype == asyauthSecret.PWB64:
			self.stype = asyauthSecret.PASSWORD
			self.secret = base64.b64decode(self.secret).decode()
		elif stype == asyauthSecret.PWHEX:
			self.stype = asyauthSecret.PASSWORD
			self.secret = bytes.fromhex(self.secret)
			if len(self.secret) % 2 == 0 and len(self.secret) > 50:
				# special case for hex passwords that are not valid utf-8 rather just raw bytes
				# for examle machine account passwords extracted from the registry
				pass
			else:
				self.secret = self.secret.decode()

		elif stype == asyauthSecret.PWPROMPT:
			import getpass
			self.stype = asyauthSecret.PASSWORD
			self.secret = getpass.getpass('Enter password: ')
	
	def build_context(self, protocol=None, target = None, **kwargs):
		if protocol is None:
			protocol = self.protocol
		
		if protocol == asyauthProtocol.NTLM:
			if self.subprotocol.type == asyauthSubProtocol.NATIVE:
				from asyauth.common.credentials.ntlm import NTLMCredential
				return NTLMCredential(self.secret, self.username, self.domain, self.stype, subprotocol=self.subprotocol, **kwargs).build_context()
			else:
				raise Exception('Unsupported subprotocol "%s"' % self.subprotocol)
		
		elif protocol == asyauthProtocol.KERBEROS:
			if self.subprotocol.type == asyauthSubProtocol.NATIVE:
				from asyauth.common.credentials.kerberos import KerberosCredential
				return KerberosCredential(
					self.secret, 
					self.username, 
					self.domain, 
					self.stype, 
					subprotocol=self.subprotocol, 
					target=target, 
					**kwargs
				).build_context()
			else:
				raise Exception('Unsupported subprotocol "%s"' % self.subprotocol)
		
		elif protocol == asyauthProtocol.SPNEGO:
			if self.subprotocol.type == asyauthSubProtocol.NATIVE:
				from asyauth.common.credentials.spnego import SPNEGOCredential
				inner = self._build_wrapper_inner(target=target, **kwargs)
				return SPNEGOCredential([inner], subprotocol=self.subprotocol).build_context()
			else:
				raise Exception('Unsupported subprotocol "%s"' % self.subprotocol)
		
		elif protocol == asyauthProtocol.SPNEGOEX:
			if self.subprotocol.type == asyauthSubProtocol.NATIVE:
				from asyauth.common.credentials.spnegoex import SPNEGOEXCredential
				inner = self._build_wrapper_inner(target=target, **kwargs)
				return SPNEGOEXCredential([inner], subprotocol=self.subprotocol).build_context()
			else:
				raise Exception('Unsupported subprotocol "%s"' % self.subprotocol)
		
		elif protocol == asyauthProtocol.CREDSSP:
			if self.subprotocol.type == asyauthSubProtocol.NATIVE:
				from asyauth.common.credentials.credssp import CREDSSPCredential
				inner = self._build_wrapper_inner(target=target, **kwargs)
				return CREDSSPCredential([inner], subprotocol=self.subprotocol).build_context()
			else:
				raise Exception('Unsupported subprotocol "%s"' % self.subprotocol)
		
		else:
			return copy.deepcopy(self)

	def _build_wrapper_inner(self, target=None, **kwargs):
		# A bare UniCredential tagged with a wrapper protocol (SPNEGO/SPNEGOEX/
		# CREDSSP) carries no explicit inner authentication protocol. Previously
		# build_context() recursed on self for the inner credential, which never
		# changed the protocol and therefore looped forever (see
		# https://github.com/skelsec/asyauth/issues/8).
		#
		# Default the inner mechanism to NTLM, mirroring how
		# SPNEGOCredential.build_context() treats plain credentials, and return a
		# concrete credential object (not a built context) which is what the
		# wrapper credential classes expect to receive.
		from asyauth import logger
		from asyauth.common.credentials.ntlm import NTLMCredential
		logger.warning(
			'No inner authentication protocol specified for %s credential; defaulting to NTLM.',
			self.protocol.name if self.protocol is not None else self.protocol,
		)
		return NTLMCredential(
			self.secret,
			self.username,
			self.domain,
			self.stype,
			subprotocol=self.subprotocol,
			**kwargs
		)

	@staticmethod
	def get_url_params():
		return {
			'timeout' : int_one,
			'dns' : str_one,
			'dnsc' : str_one, #cross-domain DNS
			'dc' : str_one,
			'dcc' : str_one, #cross-domain DC IP
			'realmc' : str_one, #cross-domain realm
		}

	@staticmethod
	def from_url(connection_url):
		from asysocks.unicomm.common.target import UniTarget, UniProto

		secret = None
		username = None
		domain = None
		stype = asyauthSecret.NONE
		protocol = asyauthProtocol.NONE
		subprotocol = SubProtocolNative()
		url_e = urlparse(connection_url)
		url_dict = url_e._asdict()
		for prop, val in url_dict.items():
			if type(val) is str:
				url_dict[prop] = unquote(val)
		url_e = url_e._replace(**url_dict)
		schemes = url_e.scheme.upper().split('+')
		if len(schemes) == 1:
			try:
				protocol = asyauthProtocol(schemes)
			except:
				pass
		else:
			auth_tags = schemes[1].replace('-','_')
			try:
				protocol = asyauthProtocol(auth_tags)
			except:
				auth_tags = schemes[1].split('-')
				if len(auth_tags) > 1:
					try:
						spt = asyauthSubProtocol(auth_tags[0])
					except:
						protocol = asyauthProtocol(auth_tags[0])
						stype = asyauthSecret(auth_tags[1])
					else:
						protocol = asyauthProtocol(auth_tags[1])
						query = None
						if url_e.query is not None:
							query = parse_qs(url_e.query)
						subprotocol = SubProtocol.from_url_params(spt, query)
						
				else:
					try:
						spt = asyauthSubProtocol(auth_tags[0])
						protocol = asyauthProtocol.NTLM
					except:
						protocol = asyauthProtocol(auth_tags[0])
						
		if url_e.username is not None:
			if url_e.username.find('\\') != -1:
				domain, username = url_e.username.split('\\')
				if domain == '.':
					domain = None
			else:
				domain = None
				username = url_e.username
		
		secret = url_e.password
		credobj = None
		if protocol == asyauthProtocol.KERBEROS:
			from asyauth.common.credentials.kerberos import KerberosCredential
			credobj = KerberosCredential
		
		elif protocol in [asyauthProtocol.NTLM, asyauthProtocol.SICILY]:
			from asyauth.common.credentials.ntlm import NTLMCredential
			credobj = NTLMCredential

		extraparams = {}
		if credobj is not None:
			extraparams = credobj.get_url_params()

		paramstemplate = UniCredential.get_url_params()
		params = dict.fromkeys(UniCredential.get_url_params(),None)
		extra = dict.fromkeys(extraparams.keys(),None)
		proxy_present = False
		if url_e.query is not None:
			query = parse_qs(url_e.query)
			for k in query:
				if k.startswith('proxy') is True:
					proxy_present = True
				if k in params:
					params[k] = paramstemplate[k](query[k])
				if k in extraparams:
					extra[k] = extraparams[k](query[k])
		
		if protocol in [asyauthProtocol.NTLM, asyauthProtocol.SICILY]:
			res = credobj(
				secret,
				username, 
				domain,
				stype,
				subprotocol=subprotocol,
				**extra
			)
			if protocol == asyauthProtocol.SICILY:
				res.protocol = asyauthProtocol.SICILY
			return res
		
		elif protocol == asyauthProtocol.KERBEROS:
			proxies = None
			if proxy_present is True:
				from asysocks.unicomm.common.proxy import UniProxyTarget
				proxies = UniProxyTarget.from_url_params(url_e.query, url_e.hostname,endpoint_port=88)

			target = None
			if extra['dc'] is not None:
				target = UniTarget(extra['dc'], 88, UniProto.CLIENT_TCP, proxies = proxies, dns=params['dns'], dc_ip=extra['dc'])

			cross_target = None
			if extra['dcc'] is not None:
				cross_target = UniTarget(extra['dcc'], 88, UniProto.CLIENT_TCP, proxies = proxies, dns=params['dnsc'], dc_ip=extra['dcc'])

			etypes = extra['etype']

			return credobj(
				secret, 
				username, 
				domain, 
				stype, 
				target = target, 
				altname = extra['altname'], 
				altdomain = extra['altdomain'],
				certdata=extra['certdata'],
				keydata=extra['keydata'],
				etypes = etypes, 
				subprotocol = subprotocol,
				cross_target = cross_target,
				cross_realm = extra['realmc'],
			)
		else:
			return UniCredential(
				secret,
				username,
				domain,
				stype,
				protocol,
				subprotocol
			)

	def __str__(self):
		import enum
		t = '==== UniCredential ====\r\n'
		for k in self.__dict__:
			val = self.__dict__[k]
			if isinstance(val, enum.IntFlag):
				val = val
			elif isinstance(val, enum.Enum):
				val = val.name
			
			t += '%s: %s\r\n' % (k, str(val))
			
		return t
	
	@staticmethod
	def get_sspi_ntlm():
		"""Returns an NTLM credential object matching the current user (Windows only)"""
		if platform.system() != 'Windows':
			raise Exception('This function only works on Windows systems!')
		from winacl.functions.highlevel import get_logon_info
		from asyauth.common.credentials.ntlm import NTLMCredential
		userinfo = get_logon_info()
		return NTLMCredential(
			None,
			userinfo['username'],
			userinfo['domain'],
			stype=asyauthSecret.NONE,
			subprotocol = SubProtocolSSPI()
		)
	
	@staticmethod
	def get_sspi_kerberos():
		"""Returns a Kerberos credential object matching the current user (Windows only)"""
		if platform.system() != 'Windows':
			raise Exception('This function only works on Windows systems!')
		from winacl.functions.highlevel import get_logon_info
		from asyauth.common.credentials.kerberos import KerberosCredential
		from asysocks.unicomm.common.target import UniTarget, UniProto
		userinfo = get_logon_info()
		dctarget = UniTarget(
			userinfo['logonserver'], 
			88, 
			UniProto.CLIENT_TCP, 
			dc_ip=userinfo['logonserver'],
			domain = userinfo['dnsdomainname'],
		)
		return KerberosCredential(
			None,
			userinfo['username'],
			userinfo['dnsdomainname'],
			stype=asyauthSecret.NONE,
			target=dctarget,
			subprotocol = SubProtocolSSPI()
		)

	@staticmethod
	def get_sspi(authtype:str):
		if platform.system() != 'Windows':
			raise Exception('This function only works on Windows systems!')
		if authtype.upper() == 'NTLM':
			credobj = UniCredential.get_sspi_ntlm()
		elif authtype.upper() == 'KERBEROS':
			credobj = UniCredential.get_sspi_kerberos()
		else:
			raise Exception('Only NTLM or KERBEROS auth types supported here!')
		return credobj

	@staticmethod
	def get_sspi_spnego(authtype:str):
		"""Returns a SPNEGO credential object matching the current user (Windows only)"""
		if platform.system() != 'Windows':
			raise Exception('This function only works on Windows systems!')
		from asyauth.common.credentials.spnego import SPNEGOCredential
		credobj = UniCredential.get_sspi(authtype)
		return SPNEGOCredential([credobj])
	
	@staticmethod
	def get_sspi_spnego(authtype:str):
		"""Returns a CREDSSP credential object matching the current user (Windows only)"""
		if platform.system() != 'Windows':
			raise Exception('This function only works on Windows systems!')
		from asyauth.common.credentials.credssp import CREDSSPCredential
		credobj = UniCredential.get_sspi(authtype)
		return CREDSSPCredential([credobj])
	
	@staticmethod
	def get_help(protocol:str = '', authprotos:str = '', extraparams:str = ''):
		"""Returns user help regarding the credential url format"""
		template = """
URL format:

	protocol+authproto-secrettype://[domain]\\username:secret@[ip|hostname]:[port]/?param1=value1&param2=value2

protocol: The protocol to use (see below)
	%s
authproto (protocol dependent): 
	%s
username: The username to authenticate with
secret: The secret to authenticate with (depends on secrettype)
domain: The domain of the user
secrettype: The type of the secret (see below)
	password/pw/pass: A plaintext password
	pwb64: A base64 encoded password
	pwprompt: Password will be prompted for on STDIN
	pwhex: A hex encoded password
	nt: NT hash
	==== Kerberos only ====
	rc4: RC4 key (Kerberos only)
	aes: AES key (any size, Kerberos only)
	aes128: AES128 key (Kerberos only)
	aes256: AES256 key (Kerberos only)
	ccache: ccache file name (only local directory)
	ccachehex: A hex encoded ccache file
	ccacheb64: A base64 encoded ccache file
	keytab: keytab file name (only local directory)
	keytabhex: A hex encoded keytab file
	keytabb64: A base64 encoded keytab file
	pfx: pfx file name (only local directory)
	pfxhex: A hex encoded pfx file
	pfxb64: A base64 encoded pfx file
	pem: pem file name (only local directory)
	pemhex: A hex encoded pem file
	pemb64: A base64 encoded pem file
	certstore: Use Windows certificate store (Windows only, Kerberos only)
	kirbi: kirbi file name (only local directory)
	kirbihex: A hex encoded kirbi file
	kirbib64: A base64 encoded kirbi file
	==== SSH Only ====
	sshprivkey: ssh private key file name (only local directory)
	sshprivkeystr: ssh private key file data in string format
	sshprivkeyb64: A base64 encoded ssh private key file

Extra parameters are in the form of param=value. The following parameters are supported:
	altname: Alternative name for certificate authentication
	altdomain: Alternative domain for certificate authentication
	etype: Supported encryption type to use (Kerberos only)
	dc: The domain controller to use (Kerberos only)
	dns: Don't use this.
	%s
"""
		return template % (protocol, authprotos, extraparams)
		#add examples

	@staticmethod
	def from_params(authproto:str, username:str = None, domain:str = None, secret:str = None, proxies=None, **kwargs):
		authproto = authproto.lower()
		protodef = authproto.split('-')
		protodef = [x.upper() for x in protodef]
		pdl = len(protodef)
		if pdl == 1 or pdl > 3:
			raise Exception('Invalid authproto: %s' % authproto)

		topprotocol = None
		protocol = None
		stype = None
		subprotocol = None
		if pdl == 2:
			# The first token may be a sub-protocol (e.g. "sspi-ntlm") or a
			# protocol followed by a secret type (e.g. "ntlm-password"). Mirror
			# from_url(): try to parse it as a sub-protocol first, and build a
			# proper SubProtocol object (the downstream code expects an object
			# with a .type attribute, not the bare enum).
			try:
				spt = asyauthSubProtocol(protodef[0])
			except ValueError:
				protocol = asyauthProtocol(protodef[0])
				stype = asyauthSecret(protodef[1])
			else:
				# SSPI/WSNET-style sub-protocols don't carry a secret type.
				protocol = asyauthProtocol(protodef[1])
				subprotocol = SubProtocol.from_url_params(spt, None)
		if pdl == 3:
			topprotocol = asyauthProtocol(protodef[0])
			protocol = asyauthProtocol(protodef[1])
			stype = asyauthSecret(protodef[2])

		if subprotocol is None:
			subprotocol = SubProtocolNative()

		authobj = UniCredential.from_parts(protocol, stype, secret, username, domain, subprotocol=subprotocol, proxies=proxies, **kwargs)
		if topprotocol is None:
			return authobj



		if topprotocol == asyauthProtocol.SPNEGO:
			if subprotocol.type == asyauthSubProtocol.NATIVE:
				from asyauth.common.credentials.spnego import SPNEGOCredential
				return SPNEGOCredential([authobj], subprotocol=subprotocol)
			else:
				raise Exception('Unsupported subprotocol "%s"' % subprotocol)

		elif topprotocol == asyauthProtocol.SPNEGOEX:
			if subprotocol.type == asyauthSubProtocol.NATIVE:
				from asyauth.common.credentials.spnegoex import SPNEGOEXCredential
				return SPNEGOEXCredential([authobj], subprotocol=subprotocol)
			else:
				raise Exception('Unsupported subprotocol "%s"' % subprotocol)

		elif topprotocol == asyauthProtocol.CREDSSP:
			if subprotocol.type == asyauthSubProtocol.NATIVE:
				from asyauth.common.credentials.credssp import CREDSSPCredential
				return CREDSSPCredential([authobj], subprotocol=subprotocol)
			else:
				raise Exception('Unsupported subprotocol "%s"' % subprotocol)

		raise Exception('Unsupported (top) protocol "%s"' % topprotocol)



	@staticmethod
	def from_parts(protocol:asyauthProtocol, stype:asyauthSecret, secret:str, username:str, domain:str, subprotocol:asyauthSubProtocol = asyauthSubProtocol.NATIVE, proxies=None, **kwargs):
		from asysocks.unicomm.common.target import UniTarget, UniProto

		if username is not None and username.find('\\') != -1:
			if domain is None or domain == '':
				domain, username = username.split('\\')
				if domain == '.':
					domain = None
			else:
				username = username.split('\\')[1]

		if domain == '':
			domain = None

		credobj = None
		if protocol == asyauthProtocol.KERBEROS:
			from asyauth.common.credentials.kerberos import KerberosCredential
			credobj = KerberosCredential

		elif protocol in [asyauthProtocol.NTLM, asyauthProtocol.SICILY]:
			from asyauth.common.credentials.ntlm import NTLMCredential
			credobj = NTLMCredential

		if protocol in [asyauthProtocol.NTLM, asyauthProtocol.SICILY]:
			res = credobj(
				secret,
				username,
				domain,
				stype,
				subprotocol=subprotocol,
				**kwargs
			)
			if protocol == asyauthProtocol.SICILY:
				res.protocol = asyauthProtocol.SICILY
			return res

		elif protocol == asyauthProtocol.KERBEROS:
			target = None
			if kwargs.get('dc') is not None:
				target = UniTarget(kwargs.get('dc'), 88, UniProto.CLIENT_TCP, proxies = proxies, dns=kwargs.get('dns'), dc_ip=kwargs.get('dc'))

			cross_target = None
			if kwargs.get('dcc') is not None:
				cross_target = UniTarget(kwargs.get('dcc'), 88, UniProto.CLIENT_TCP, proxies = proxies, dns=kwargs.get('dnsc'), dc_ip=kwargs.get('dcc'))

			return credobj(
				secret,
				username,
				domain,
				stype,
				target = target,
				altname = kwargs.get('altname'),
				altdomain = kwargs.get('altdomain'),
				certdata=kwargs.get('certdata'),
				keydata=kwargs.get('keydata'),
				etypes = kwargs.get('etype'),
				subprotocol = subprotocol,
				cross_target = cross_target,
				cross_realm = kwargs.get('realmc'),
			)
		else:
			return UniCredential(
				secret,
				username,
				domain,
				stype,
				protocol,
				subprotocol
			)

	@staticmethod
	def add_arguments(parser):
		parser.add_argument('authproto', type=str, help='The authentication protocol to use. Supported auth protocols determined by the network protocol.')
		parser.add_argument('username', type=str, help='The username to authenticate with. Can be in the form of domain\\username or username.')
		parser.add_argument('secret', type=str, help='The secret to authenticate with. This can be password, file path, or data in hex or base64 format')
		#parser.add_argument('--altname', type=str, help='Alternative name for certificate authentication')
		#parser.add_argument('--altdomain', type=str, help='Alternative domain for certificate authentication')
		parser.add_argument('--etype', type=int, help='Kerberos only: Supported encryption type to use')
		parser.add_argument('--dc', type=str, help='Kerberos only: The domain controller to use')
		parser.add_argument('--dcc', type=str, help='Kerberos only: Cross-domain DC IP')
		parser.add_argument('--dns', type=str, help='Kerberos only: Don\'t use this.')
		parser.add_argument('--dnsc', type=str, help='Kerberos only: Cross-domain DNS')
		parser.add_argument('--realmc', type=str, help='Kerberos only: Cross-domain realm')
		parser.add_argument('--certdata', type=str, help='Kerberos only: Certificate data')
		parser.add_argument('--keydata', type=str, help='Kerberos only: Key data')
		parser.add_argument('--ntlmnosig', type=bool, help='NTLM only: Disable signing and sealing')
		parser.add_argument('--ntlmworkstation', type=str, help='NTLM only: Workstation name')
		parser.add_argument('--ntlmdomain', type=str, help='NTLM only: Domain name')
		parser.add_argument('--ntlmflags', type=int, help='NTLM only: Flags')
		parser.add_argument('--ntlmversionmajor', type=int, help='NTLM only: Windows major version (default: 10)')
		parser.add_argument('--ntlmversionminor', type=int, help='NTLM only: Windows minor version (default: 0)')
		parser.add_argument('--ntlmversionbuild', type=int, help='NTLM only: Windows build number (default: 15063)')

		return parser

	@staticmethod
	def from_args(args):
		kwargs = args.__dict__.copy()
		kwargs.pop('authproto')
		kwargs.pop('username')
		kwargs.pop('secret')
		kwargs.pop('protocol')
		kwargs.pop('target')
		if kwargs.get('proxies') is not None:
			kwargs.pop('proxies')
		kwargs.pop('dc')
		kwargs.pop('dcc')
		kwargs.pop('dns')
		kwargs.pop('dnsc')
		kwargs.pop('realmc')
		kwargs.pop('certdata')
		kwargs.pop('keydata')
		kwargs.pop('ntlmnosig')
		kwargs.pop('ntlmworkstation')
		kwargs.pop('ntlmdomain')
		kwargs.pop('ntlmflags')
		kwargs.pop('ntlmversionmajor')
		kwargs.pop('ntlmversionminor')
		kwargs.pop('ntlmversionbuild')
		return UniCredential.from_params(args.authproto, username=args.username, secret=args.secret, proxies=None,
			dc=args.dc,
			dcc=args.dcc,
			dns=args.dns,
			dnsc=args.dnsc,
			realmc=args.realmc,
			certdata=args.certdata,
			keydata=args.keydata,
			ntlmnosig=args.ntlmnosig,
			ntlmworkstation=args.ntlmworkstation,
			ntlmdomain=args.ntlmdomain,
			ntlmflags=args.ntlmflags,
			ntlmversionmajor=args.ntlmversionmajor,
			ntlmversionminor=args.ntlmversionminor,
			ntlmversionbuild=args.ntlmversionbuild,
			**kwargs
		)

	@staticmethod
	def argparser_help():
		return """
authproto: The authentication protocol to use. Supported protocols:
	none-password
	none-pw
	none-pwhex
	none-pwb64
	none-pwprompt
	simple-password
	simple-pw
	simple-pwhex
	simple-pwb64
	simple-pwprompt
	sshprivkey
	sshprivkeystr
	sshprivkeyb64
	sys
	null
	plain-password
	plain-pwhex
	plain-pwb64
	plain-pwprompt
	plain-pw
	sicily-password
	sicily-pw
	sicily-pwhex
	sicily-pwb64
	sicily-pwprompt
	sicily-nt
	sicily-rc4
	ntlm-password
	ntlm-none
	ntlm-pw
	ntlm-pwhex
	ntlm-pwb64
	ntlm-pwprompt
	ntlm-nt
	ntlm-rc4
	# kerberos
	kerberos-password
	kerberos-pw
	kerberos-pwhex
	kerberos-pwb64
	kerberos-nt
	kerberos-rc4
	kerberos-aes
	kerberos-aes128
	kerberos-aes256
	kerberos-ccache
	kerberos-ccachehex
	kerberos-ccacheb64
	kerberos-keytab
	kerberos-keytabhex
	kerberos-keytabb64
	kerberos-pfx
	kerberos-pfxhex
	kerberos-pfxb64
	kerberos-pem
	kerberos-certstore
	kerberos-kirbi
	kerberos-kirbihex
	kerberos-kirbib64
	kerberos-certstore

	credssp-ntlm-password
	credssp-ntlm-pw
	credssp-ntlm-pwhex
	credssp-ntlm-pwb64
	credssp-ntlm-pwprompt
	credssp-ntlm-nt
	credssp-ntlm-rc4
	credssp-ntlm-password
	credssp-ntlm-pw
	credssp-ntlm-pwhex
	credssp-ntlm-pwb64
	credssp-ntlm-pwprompt
	credssp-ntlm-nt
	credssp-ntlm-rc4
	credssp-kerberos-password
	credssp-kerberos-pw
	credssp-kerberos-pwhex
	credssp-kerberos-pwb64
	credssp-kerberos-nt
	credssp-kerberos-rc4
	credssp-kerberos-aes
	credssp-kerberos-aes128
	credssp-kerberos-aes256
	credssp-kerberos-ccache
	credssp-kerberos-ccachehex
	credssp-kerberos-ccacheb64
	credssp-kerberos-keytab
	credssp-kerberos-keytabhex
	credssp-kerberos-keytabb64
	credssp-kerberos-pfx
	credssp-kerberos-pfxhex
	credssp-kerberos-pfxb64
	credssp-kerberos-pem
	credssp-kerberos-certstore
	credssp-kerberos-kirbi
	credssp-kerberos-kirbihex
	credssp-kerberos-kirbib64

	spnego-ntlm-password
	spnego-ntlm-none
	spnego-ntlm-pw
	spnego-ntlm-pwhex
	spnego-ntlm-pwb64
	spnego-ntlm-pwprompt
	spnego-ntlm-nt
	spnego-ntlm-rc4
	spnego-ntlm-password
	spnego-ntlm-pw
	spnego-ntlm-pwhex
	spnego-ntlm-pwb64
	spnego-ntlm-pwprompt
	spnego-ntlm-nt
	spnego-ntlm-rc4
	spnego-kerberos-password
	spnego-kerberos-pw
	spnego-kerberos-pwhex
	spnego-kerberos-pwb64
	spnego-kerberos-nt
	spnego-kerberos-rc4
	spnego-kerberos-aes
	spnego-kerberos-aes128
	spnego-kerberos-aes256
	spnego-kerberos-ccache
	spnego-kerberos-ccachehex
	spnego-kerberos-ccacheb64
	spnego-kerberos-keytab
	spnego-kerberos-keytabhex
	spnego-kerberos-keytabb64
	spnego-kerberos-pfx
	spnego-kerberos-pfxhex
	spnego-kerberos-pfxb64
	spnego-kerberos-pem
	spnego-kerberos-certstore
	spnego-kerberos-kirbi
	spnego-kerberos-kirbihex
	spnego-kerberos-kirbib64

	sspi-ntlm
	sspi-kerberos

"""
from asyauth.common.credentials.credssp import CREDSSPCredential
from asyauth.common.credentials.kerberos import KerberosCredential
from asyauth.common.credentials.ntlm import NTLMCredential
from asyauth.common.credentials.spnego import SPNEGOCredential
from asyauth.common.credentials.spnegoex import SPNEGOEXCredential


__all__ = [
	'CREDSSPCredential', 
	'KerberosCredential', 
	'NTLMCredential', 
	'SPNEGOCredential',
	'SPNEGOEXCredential',
]
