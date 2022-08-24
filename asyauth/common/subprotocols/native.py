from asyauth.common.constants import asyauthSubProtocol
from asyauth.common.subprotocols import SubProtocol


class SubProtocolNative(SubProtocol):
	def __init__(self):
		SubProtocol.__init__(self, asyauthSubProtocol.NATIVE)

	@staticmethod
	def from_url_params(query_params = None):
		return SubProtocolNative()