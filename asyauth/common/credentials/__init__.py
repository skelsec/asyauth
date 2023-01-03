import base64
import platform
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
			self.secret = base64.b64decode(self.secret)
		elif stype == asyauthSecret.PWHEX:
			self.stype = asyauthSecret.PASSWORD
			self.secret = bytes.fromhex(self.secret)
		elif stype == asyauthSecret.PWPROMPT:
			import getpass
			self.stype = asyauthSecret.PASSWORD
			self.secret = getpass.getpass('Enter password: ')
	
	def build_context(self):
		# override this function
		raise NotImplementedError()

	@staticmethod
	def get_url_params():
		return {
			'timeout' : int_one,
			'dns' : str_one,
			'dc' : str_one,
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
				proxies = UniProxyTarget.from_url_params(connection_url, endpoint_port=88)

			target = None
			if extra['dc'] is not None:
				target = UniTarget(extra['dc'], 88, UniProto.CLIENT_TCP, proxies = proxies, dns=params['dns'], dc_ip=extra['dc'])

			etypes = extra['etype'] if extra['etype'] is not None else [23,17,18]

			return credobj(
				secret, 
				username, 
				domain, 
				stype, 
				target = target, 
				altname = extra['altname'], 
				altdomain = extra['altdomain'], 
				etypes = etypes, 
				subprotocol = subprotocol
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
		dctarget = UniTarget(userinfo['logonserver'], 88, UniProto.CLIENT_TCP)
		return KerberosCredential(
			None,
			userinfo['username'],
			userinfo['domain'],
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