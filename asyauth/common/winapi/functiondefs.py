import enum
import datetime
import ctypes

from asyauth.common.winapi.constants import SECBUFFER_TYPE, SEC_E, ISC_REQ
from minikerberos.gssapi.gssapi import GSSWrapToken

windll      = ctypes.windll
byref       = ctypes.byref
addressof   = ctypes.addressof
sizeof      = ctypes.sizeof
SIZEOF      = ctypes.sizeof

LPSTR   = ctypes.c_char_p
CHAR    = ctypes.c_char
PCHAR   = LPSTR
DWORD   = ctypes.c_uint32
POINTER = ctypes.POINTER
LONG    = ctypes.c_int32
ULONG   = ctypes.c_uint32
LPVOID  = ctypes.c_void_p
BYTE    = ctypes.c_ubyte
PVOID   = LPVOID
PPVOID  = POINTER(PVOID)
LPBYTE  = POINTER(BYTE)
LPULONG = POINTER(ULONG)
PULONG  = LPULONG

class Structure(ctypes.Structure):
	if sizeof(ctypes.c_void_p) == 4:
		_pack_ = 1


# call API to get max token size, or..
maxtoken_size = 2880 # bytes

_FILETIME_null_date = datetime.datetime(1601, 1, 1, 0, 0, 0)
def FiletimeToDateTime(ft):
	timestamp = (ft.dwHighDateTime << 32) + ft.dwLowDateTime
	return _FILETIME_null_date + datetime.timedelta(microseconds=timestamp/10)

#timestamp is LARGE_INTEGER
#same as FILETIME structure

#https://docs.microsoft.com/en-us/windows/desktop/api/minwinbase/ns-minwinbase-filetime
class FILETIME(Structure):
	_fields_ = [
		("dwLowDateTime",   DWORD),
		("dwHighDateTime",   DWORD),
	]
PFILETIME = POINTER(FILETIME)
TimeStamp = FILETIME
PTimeStamp = PFILETIME

SEC_CHAR = CHAR
PSEC_CHAR = PCHAR

class LUID(Structure):
	_fields_ = [
		("LowPart",	 DWORD),
		("HighPart",	LONG),
	]

PLUID = POINTER(LUID)

class SEC_CHANNEL_BINDINGS(Structure):
	_fields_ = [
		('dwInitiatorAddrType',ULONG),
		('cbInitiatorLength',ULONG),
		('dwInitiatorOffset',ULONG),
		('dwAcceptorAddrType',ULONG),
		('cbAcceptorLength',ULONG),
		('dwAcceptorOffset',ULONG),
		('cbApplicationDataLength',ULONG),
		('dwApplicationDataOffset',ULONG),
		('Buffer', LPVOID)
	]
	
# https://docs.microsoft.com/en-us/windows/desktop/api/sspi/ns-sspi-secpkgcontext_sessionkey
class SecPkgContext_SessionKey(Structure):
	_fields_ = [('SessionKeyLength',ULONG),('SessionKey',LPBYTE)]
	
	@property
	def Buffer(self):
		return ctypes.string_at(self.SessionKey, size=self.SessionKeyLength)

# https://github.com/benjimin/pywebcorp/blob/master/pywebcorp/ctypes_sspi.py
class SecHandle(ctypes.Structure): 
	
	_fields_ = [('dwLower',PULONG),('dwUpper',PULONG)]
	def __init__(self): # populate deeply (empty memory fields) rather than shallow null POINTERs.
		ctypes.Structure.__init__(self, ctypes.pointer(ULONG()), ctypes.pointer(ULONG()))

class SecBuffer(Structure):
	"""Stores a memory buffer: size, type-flag, and POINTER. 
	The type can be empty (0) or token (2).
	InitializeSecurityContext will write to the buffer that is flagged "token"
	and update the size, or else fail 0x80090321=SEC_E_BUFFER_TOO_SMALL."""	
	_fields_ = [('cbBuffer',ULONG),('BufferType',ULONG),('pvBuffer',PVOID)]
	def __init__(self, token=b'\x00'*maxtoken_size, buffer_type = SECBUFFER_TYPE.SECBUFFER_TOKEN):
		buf = ctypes.create_string_buffer(token, size=len(token)) 
		Structure.__init__(self,sizeof(buf),buffer_type.value,ctypes.cast(ctypes.pointer(buf),PVOID))
	@property
	def Buffer(self):
		return (SECBUFFER_TYPE(self.BufferType), ctypes.string_at(self.pvBuffer, size=self.cbBuffer))	 

class SecBufferDesc(Structure):
	"""Descriptor stores SECBUFFER_VERSION=0, number of buffers (e.g. one),
	and POINTER to an array of SecBuffer structs."""
	_fields_ = [('ulVersion',ULONG),('cBuffers',ULONG),('pBuffers',POINTER(SecBuffer))]
	def __init__(self, secbuffers = None):
		#secbuffers = a list of security buffers (SecBuffer)
		if secbuffers is not None:
			Structure.__init__(self,0,len(secbuffers),(SecBuffer * len(secbuffers))(*secbuffers))
		else:
			Structure.__init__(self,0,1,ctypes.pointer(SecBuffer()))
	def __getitem__(self, index):
		return self.pBuffers[index]
		
	@property
	def Buffers(self):
		data = []
		for i in range(self.cBuffers):
			data.append(self.pBuffers[i].Buffer)
		return data
		
PSecBufferDesc = POINTER(SecBufferDesc)
PSecHandle     = POINTER(SecHandle)
CredHandle     = SecHandle
PCredHandle    = PSecHandle
CtxtHandle     = SecHandle
PCtxtHandle    = PSecHandle


class DecryptFlags(enum.Enum):										
	SIGN_ONLY = 0
	SECQOP_WRAP_NO_ENCRYPT = 2147483649 # same as KERB_WRAP_NO_ENCRYPT
	
def FreeContextBuffer(secbuff):
	def errc(result, func, arguments):
		if SEC_E(result) == SEC_E.OK:
			return SEC_E(result)
		raise Exception('%s failed with error code %s (%s)' % ('DecryptMessage', result, SEC_E(result)))
	
	_FreeContextBuffer = windll.Secur32.FreeContextBuffer
	_FreeContextBuffer.argtypes = [PVOID]
	_FreeContextBuffer.restype  = DWORD
	_FreeContextBuffer.errcheck  = errc
	
	res = _FreeContextBuffer(byref(secbuff))
	return

#https://github.com/mhammond/pywin32/blob/d64fac8d7bda2cb1d81e2c9366daf99e802e327f/win32/Lib/sspi.py#L108
#https://docs.microsoft.com/en-us/windows/desktop/secauthn/using-sspi-with-a-windows-sockets-client
#https://msdn.microsoft.com/en-us/library/Aa374712(v=VS.85).aspx
def AcquireCredentialsHandle(client_name, package_name, tragetspn, cred_usage, pluid = None, authdata = None):
	def errc(result, func, arguments):
		if SEC_E(result) == SEC_E.OK:
			return result
		raise Exception('%s failed with error code %s (%s)' % ('AcquireCredentialsHandle', result, SEC_E(result)))
		
	_AcquireCredentialsHandle = windll.Secur32.AcquireCredentialsHandleA
	_AcquireCredentialsHandle.argtypes = [PSEC_CHAR, PSEC_CHAR, ULONG, PLUID, PVOID, PVOID, PVOID, PCredHandle, PTimeStamp]
	_AcquireCredentialsHandle.restype  = DWORD
	_AcquireCredentialsHandle.errcheck  = errc
	
	#TODO: package_name might be different from version to version. implement functionality to poll it properly!
	
	cn = None
	if client_name:
		cn = LPSTR(client_name.encode('ascii'))
	pn = LPSTR(package_name.encode('ascii'))
	
	creds = CredHandle()
	ts = TimeStamp()
	res = _AcquireCredentialsHandle(cn, pn, cred_usage, pluid, authdata, None, None, byref(creds), byref(ts))
	return creds
	
# https://msdn.microsoft.com/en-us/library/windows/desktop/aa375507(v=vs.85).aspx
def InitializeSecurityContext(creds, target, ctx = None, flags = ISC_REQ.INTEGRITY | ISC_REQ.CONFIDENTIALITY | ISC_REQ.SEQUENCE_DETECT | ISC_REQ.REPLAY_DETECT, TargetDataRep  = 0, token = None, cb_data = None):
	def errc(result, func, arguments):
		if SEC_E(result) in [SEC_E.OK, SEC_E.COMPLETE_AND_CONTINUE, SEC_E.COMPLETE_NEEDED, SEC_E.CONTINUE_NEEDED, SEC_E.INCOMPLETE_CREDENTIALS]:
			return SEC_E(result)
		raise Exception('%s failed with error code %s (%s) Target: %s' % ('InitializeSecurityContext', result, SEC_E(result), target))
		
	_InitializeSecurityContext = windll.Secur32.InitializeSecurityContextA
	_InitializeSecurityContext.argtypes = [PCredHandle, PCtxtHandle, PSEC_CHAR, ULONG, ULONG, ULONG, PSecBufferDesc, ULONG, PCtxtHandle, PSecBufferDesc, PULONG, PTimeStamp]
	_InitializeSecurityContext.restype  = DWORD
	_InitializeSecurityContext.errcheck  = errc
	if target:
		ptarget = LPSTR(target.encode('ascii'))
	else:
		ptarget = None
	newbuf = SecBufferDesc()
	outputflags = ULONG()
	expiry = TimeStamp()
	
	sb = []
	if token:
		sb = [SecBuffer(token)]
	if cb_data:
		cb = b'\x00'*24 + len(cb_data).to_bytes(4, byteorder='little', signed=False) + (32).to_bytes(4, byteorder='little', signed=False) + cb_data
		sb.append(SecBuffer(token=cb, buffer_type=SECBUFFER_TYPE.SECBUFFER_CHANNEL_BINDINGS))
	token = SecBufferDesc(sb)

	if not ctx:
		ctx = CtxtHandle()
		res = _InitializeSecurityContext(byref(creds), None, ptarget, int(flags), 0 ,TargetDataRep, byref(token) if token else None, 0, byref(ctx), byref(newbuf), byref(outputflags), byref(expiry))
	else:
		res = _InitializeSecurityContext(byref(creds), byref(ctx), ptarget, int(flags), 0 ,TargetDataRep, byref(token) if token else None, 0, byref(ctx), byref(newbuf), byref(outputflags), byref(expiry))
	
	data = newbuf.Buffers
	return res, ctx, data[0][1], ISC_REQ(outputflags.value), expiry
	
def DecryptMessage(ctx, token, data, message_no = 0):
	def errc(result, func, arguments):
		if SEC_E(result) == SEC_E.OK:
			return SEC_E(result)
		raise Exception('%s failed with error code %s (%s)' % ('DecryptMessage', result, SEC_E(result)))
		
	_DecryptMessage = windll.Secur32.DecryptMessage
	_DecryptMessage.argtypes = [PCtxtHandle, PSecBufferDesc, ULONG, PULONG]
	_DecryptMessage.restype  = DWORD
	_DecryptMessage.errcheck  = errc
	
	secbuffers = []
	secbuffers.append(SecBuffer(token=token, buffer_type = SECBUFFER_TYPE.SECBUFFER_TOKEN))
	secbuffers.append(SecBuffer(token=data[:-1], buffer_type = SECBUFFER_TYPE.SECBUFFER_DATA))
	secbuffers.append(SecBuffer(token=data[-1:],buffer_type = SECBUFFER_TYPE.SECBUFFER_PADDING))
	
	
	data = SecBufferDesc(secbuffers)
	
	flags = ULONG()
	message_no = ULONG(message_no)

	res = _DecryptMessage(byref(ctx), byref(data), message_no, byref(flags))
	
	return data.Buffers

def GetSequenceNumberFromEncryptdataKerberos(ctx, unwrap=True):
	def errc(result, func, arguments):
		if SEC_E(result) == SEC_E.OK:
			return SEC_E(result)
		raise Exception('%s failed with error code %s (%s)' % ('EncryptMessage', result, SEC_E(result)))
		
	_EncryptMessage = windll.Secur32.EncryptMessage
	_EncryptMessage.argtypes = [PCtxtHandle, ULONG, PSecBufferDesc, ULONG]
	_EncryptMessage.restype  = DWORD
	_EncryptMessage.errcheck  = errc
	
	data = b'HAHAHAHAHAHAHAHA'

	secbuffers = []
	secbuffers.append(SecBuffer(token=b'\x00'*1024, buffer_type = SECBUFFER_TYPE.SECBUFFER_TOKEN)) #tthe correct size should be checked but that's another api call..
	secbuffers.append(SecBuffer(token=data, buffer_type = SECBUFFER_TYPE.SECBUFFER_DATA))
	
	data = SecBufferDesc(secbuffers)
	
	flags = ULONG(1)
	message_no = ULONG(0)

	res = _EncryptMessage(ctx, flags, byref(data), message_no)
	if unwrap is True:
		tok = GSSWrapToken.from_bytes(data.Buffers[0][1])
		return tok.SND_SEQ
	return data.Buffers[0][1]
	
def EncryptMessage(ctx, data, message_no = 0, fQOP = None):
	#raise NotImplementedError()
	def errc(result, func, arguments):
		if SEC_E(result) == SEC_E.OK:
			return SEC_E(result)
		raise Exception('%s failed with error code %s (%s)' % ('EncryptMessage', result, SEC_E(result)))
		
	_EncryptMessage = windll.Secur32.EncryptMessage
	_EncryptMessage.argtypes = [PCtxtHandle, ULONG, PSecBufferDesc, ULONG]
	_EncryptMessage.restype  = DWORD
	_EncryptMessage.errcheck  = errc
	
	secbuffers = []
	#secbuffers.append(SecBuffer(token=b'\x00'*1024, buffer_type = SECBUFFER_TYPE.SECBUFFER_STREAM_HEADER))
	secbuffers.append(SecBuffer(token=b'\x00'*1024, buffer_type = SECBUFFER_TYPE.SECBUFFER_TOKEN))
	secbuffers.append(SecBuffer(token=data, buffer_type = SECBUFFER_TYPE.SECBUFFER_DATA))
	secbuffers.append(SecBuffer(token =b'\x00'*1024,buffer_type = SECBUFFER_TYPE.SECBUFFER_PADDING))
	#secbuffers.append(SecBuffer(token = b'',buffer_type = SECBUFFER_TYPE.SECBUFFER_EMPTY))
	
	data = SecBufferDesc(secbuffers)
	
	flags = ULONG(1)
	message_no = ULONG(message_no)

	res = _EncryptMessage(ctx, flags, byref(data), message_no)
	return res, data.Buffers
	

	
# https://docs.microsoft.com/en-us/windows/desktop/api/sspi/nf-sspi-querycontextattributesa
def QueryContextAttributes(ctx, attr, sec_struct):
	#attr = SECPKG_ATTR enum
	def errc(result, func, arguments):
		if SEC_E(result) == SEC_E.OK:
			return SEC_E(result)
		raise Exception('%s failed with error code %s (%s)' % ('QueryContextAttributes', result, SEC_E(result)))
		
	_QueryContextAttributes = windll.Secur32.QueryContextAttributesW
	_QueryContextAttributes.argtypes = [PCtxtHandle, ULONG, PVOID]
	_QueryContextAttributes.restype  = DWORD
	_QueryContextAttributes.errcheck  = errc
	
	res = _QueryContextAttributes(byref(ctx), attr.value, byref(sec_struct))
	
	return


# https://docs.microsoft.com/en-us/windows/win32/api/sspi/nf-sspi-setcontextattributesw
def SetContextAttributes(ctx, attr, data):
	#attr = SECPKG_ATTR enum
	def errc(result, func, arguments):
		if SEC_E(result) == SEC_E.OK:
			return SEC_E(result)
		raise Exception('%s failed with error code %s (%s)' % ('SetContextAttributes', result, SEC_E(result)))
		
	_SetContextAttributes = windll.Secur32.SetContextAttributesW
	_SetContextAttributes.argtypes = [PCtxtHandle, ULONG, PVOID, ULONG]
	_SetContextAttributes.restype  = DWORD
	_SetContextAttributes.errcheck  = errc

	print('set data: %s' % data)
	print('set attr: %s' % attr)
	data_len = ULONG(len(data))
	data_buff = ctypes.create_string_buffer(data, len(data))
	
	res = _SetContextAttributes(byref(ctx), attr.value, data_buff, data_len)
	
	return

