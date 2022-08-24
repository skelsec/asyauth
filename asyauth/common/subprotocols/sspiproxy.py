from typing import List
from asyauth.common.constants import asyauthSubProtocol
from asyauth.common.subprotocols import SubProtocol
from asysocks.unicomm.common.proxy import UniProxyTarget

class SubProtocolSSPIProxy(SubProtocol):
	def __init__(self, proto:str, host:str, port:int, agentid:str, proxies:List[UniProxyTarget]):
		SubProtocol.__init__(self, asyauthSubProtocol.SSPIPROXY)
		self.proto = proto
		self.host = host
		self.port = port
		self.agentid = agentid
		self.proxies = proxies
	
	def get_url(self):
		return '%s://%s:%s' % (self.proto, self.host, self.port)
	
	@staticmethod
	def from_url_params(query_params = None):
		if 'authagentid' not in query_params:
			if 'agentid' not in query_params:
				raise Exception('SSPIProxy subprotocol requires "agentid" parameter!')
		if 'authhost' not in query_params:
			raise Exception('SSPIProxy subprotocol requires "authhost" parameter!')
		if 'authport' not in query_params:
			raise Exception('SSPIProxy subprotocol requires "authport" parameter!')
		if 'authproto' not in query_params:
			authproto = 'ws'
		else:
			authproto = str(query_params['authproto'][0])

		authhost = str(query_params['authhost'][0])
		authport = str(query_params['authport'][0])
		proxy = UniProxyTarget.from_url_params(query_params, authhost, endpoint_port = authport)

		return SubProtocolSSPIProxy(
			authproto,
			authhost,
			authport,
			str(query_params['authagentid'][0]),
			proxy
		)