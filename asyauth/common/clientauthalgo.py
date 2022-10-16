from typing import Tuple
from asyauth.common.winapi.constants import ISC_REQ
from asyauth.common.credentials import UniCredential

class ClientAuthAlgo:
	def __init__(self, credential:UniCredential):
		pass

	#def is_guest(self):
	#	raise NotImplementedError()

	def get_seq_number(self) -> int:
		"""Returns the !INITIAL! sequence number"""
		raise NotImplementedError()
	
	def get_session_key(self) -> bytes:
		"""Returns session key bytes"""
		raise NotImplementedError()

	async def encrypt(self, data:bytes, sequence_no:int):
		"""Encryptes message"""
		raise NotImplementedError()

	async def decrypt(self, data:bytes, sequence_no:int, direction='init', auth_data=None) -> Tuple[bytes, Exception]:
		"""Decrypts message. Also performs integrity checking."""
		raise NotImplementedError()

	async def sign(self, data:bytes, message_no:int, direction:str=None, reset_cipher:bool = False) -> bytes:
		"""Singing outgoing messages. The reset_cipher parameter is needed for calculating mechListMIC."""
		raise NotImplementedError()

	async def verify(self, data:bytes, signature:bytes) -> bool:
		"""Verifying message signature"""
		raise NotImplementedError()
	
	def signing_needed(self) -> bool:
		"""Returns wether signing is negotiated for this client"""
		raise NotImplementedError()
	
	def encryption_needed(self) -> bool:
		"""Returns wether encryption is negotiated for this client"""
		raise NotImplementedError()
		
	def get_session_key(self) -> bytes:
		"""Returns the session key bytes"""
		raise NotImplementedError()

	async def authenticate(self, authData:bytes, flags:ISC_REQ = None, cb_data:bytes = None, spn:str=None): # -> Tuple[bytes, bool, Exception]
		raise NotImplementedError()