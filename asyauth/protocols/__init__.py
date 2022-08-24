from typing import Tuple


class ClientAuth:
	def __init__(self, settings):
		self.settings = settings
	
	def get_seq_number(self) -> bool:
		"""
		Returns the initial sequence number.
		"""
		raise NotImplementedError()
	
	def signing_needed(self) -> bool:
		"""
		Checks if integrity protection was negotiated
		"""
		raise NotImplementedError()
	
	def encryption_needed(self) -> bool:
		"""
		Checks if confidentiality was negotiated
		"""
		raise NotImplementedError()
	
	def get_session_key(self) -> bytes:
		"""
		Returns the negotiated session key
		"""
		raise NotImplementedError()
				
	async def sign(self, data:bytes, seq_number:int) -> bytes:
		"""
		Signs a message. 
		"""
		raise NotImplementedError()
		
	async def encrypt(self, data:bytes, seq_number:int) -> bytes:
		"""
		Encrypts a message. 
		"""
		raise NotImplementedError()
		
	async def decrypt(self, data:bytes) -> bytes:
		"""
		Decrypts message. Also performs integrity checking.
		"""
		raise NotImplementedError()
	
	
	async def authenticate(self, token:bytes) -> Tuple[bytes, bool, Exception]:
		"""
		This function is called (multiple times depending on the protocol) to perform authentication.

		returns a tuple of (token, to_continue, error)
		"""
		return None, None, None