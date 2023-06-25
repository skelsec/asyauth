from re import sub
from asyauth.common.constants import asyauthSubProtocol
from urllib.parse import urlparse, parse_qs

class SubProtocol:
	def __init__(self, type:asyauthSubProtocol):
		self.type = type
	
	@staticmethod
	def from_url_params(subprotocol:asyauthSubProtocol, query_params):
		if subprotocol == asyauthSubProtocol.NATIVE:
			return SubProtocolNative.from_url_params(query_params)
		if subprotocol == asyauthSubProtocol.SSPI:
			return SubProtocolSSPI.from_url_params(query_params)
		if subprotocol == asyauthSubProtocol.SSPIPROXY:
			return SubProtocolSSPIProxy.from_url_params(query_params)
		if subprotocol == asyauthSubProtocol.WSNET:
			return SubProtocolWSNet.from_url_params(query_params)
		if subprotocol == asyauthSubProtocol.WSNETDIRECT:
			return SubProtocolWSNetDirect.from_url_params(query_params)
		raise Exception("asyauth unknown subprotocol %s" % subprotocol)

from asyauth.common.subprotocols.native import SubProtocolNative
from asyauth.common.subprotocols.sspi import SubProtocolSSPI
from asyauth.common.subprotocols.sspiproxy import SubProtocolSSPIProxy
from asyauth.common.subprotocols.wsnet import SubProtocolWSNet
from asyauth.common.subprotocols.wsnetdirect import SubProtocolWSNetDirect


__all__ = ['SubProtocolNative', 'SubProtocolSSPI', 'SubProtocolSSPIProxy', 'SubProtocolWSNet', 'SubProtocolWSNetDirect']

