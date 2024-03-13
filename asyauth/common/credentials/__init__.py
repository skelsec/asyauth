import base64
import platform
import copy
from urllib.parse import urlparse, parse_qs
from asyauth.utils.paramprocessor import str_one, int_one, bool_one
from asyauth.common.constants import asyauthSecret, asyauthProtocol, asyauthSubProtocol
from asyauth.common.subprotocols import SubProtocol, SubProtocolNative, SubProtocolSSPI

class UniCredential:
	def __init__(self, secret:str = None, username:str = None, domain:str = None, stype:asyauthSecret = asyauthSecret.NONE, protocol:asyauthProtocol = None, subprotocol:SubProtocol = SubProtocolNative()):
		self.domain = domain
		self.username = username
		self.secret = secret
		self.stype = stype
		self.protocol = protocol
		self.subprotocol = subprotocol

		if stype in [asyauthSecret.PASS, asyauthSecret.PW]:
			self.stype = asyauthSecret.PASSWORD
		elif stype == asyauthSecret.PWB64:
			self.stype = asyauthSecret.PASSWORD
			self.secret = base64.b64decode(self.secret).decode()
		elif stype == asyauthSecret.PWHEX:
			self.stype = asyauthSecret.PASSWORD
			self.secret = bytes.fromhex(self.secret).decode()
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
				return SPNEGOCredential([self.build_context(target=target, **kwargs)], subprotocol=self.subprotocol).build_context()
			else:
				raise Exception('Unsupported subprotocol "%s"' % self.subprotocol)
		
		elif protocol == asyauthProtocol.SPNEGOEX:
			if self.subprotocol.type == asyauthSubProtocol.NATIVE:
				from asyauth.common.credentials.spnegoex import SPNEGOEXCredential
				return SPNEGOEXCredential([self.build_context(target=target, **kwargs)], subprotocol=self.subprotocol).build_context()
			else:
				raise Exception('Unsupported subprotocol "%s"' % self.subprotocol)
		
		elif protocol == asyauthProtocol.CREDSSP:
			if self.subprotocol.type == asyauthSubProtocol.NATIVE:
				from asyauth.common.credentials.credssp import CREDSSPCredential
				return CREDSSPCredential([self.build_context(target=target, **kwargs)], subprotocol=self.subprotocol).build_context()
			else:
				raise Exception('Unsupported subprotocol "%s"' % self.subprotocol)
		
		else:
			return copy.deepcopy(self)
		
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

			etypes = extra['etype'] if extra['etype'] is not None else [23,17,18]

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