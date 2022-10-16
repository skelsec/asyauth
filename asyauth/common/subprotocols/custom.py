from asyauth.common.constants import asyauthSubProtocol
from asyauth.common.subprotocols import SubProtocol


class SubProtocolCustom(SubProtocol):
	def __init__(self, factoryobj):
		SubProtocol.__init__(self, asyauthSubProtocol.CUSTOM)
		self.factoryobj = factoryobj

	@staticmethod
	def from_url_params(query_params = None):
		raise NotImplementedError()
	
	def build_context(self, credential):
		return self.factoryobj.build_context(credential)
	
	def __deepcopy__(self, memo=None):
		return SubProtocolCustom(self.factoryobj)