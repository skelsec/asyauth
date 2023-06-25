from asyauth.common.constants import asyauthSubProtocol
from asyauth.common.subprotocols import SubProtocol

class SubProtocolWSNetDirect(SubProtocol):
	def __init__(self, ip:str, port:int, proto:str = 'ws'):
		SubProtocol.__init__(self, asyauthSubProtocol.WSNETDIRECT)
		self.ip = ip
		self.port = port
		self.proto = proto

	def get_url(self):
		return "%s://%s:%s" % (self.proto, self.ip, self.port)
	
	@staticmethod
	def from_url_params(query_params = None):
		if 'wsip' not in query_params:
			raise Exception("Query parameter 'wsip' missing")
		ip = query_params['wsip'][0]
		port = query_params.get('wsport', [8700])[0]
		proto = query_params.get('wsproto', ['ws'])[0]
		return SubProtocolWSNetDirect(ip, port, proto)