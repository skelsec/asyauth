import enum



class SSPIResult(enum.Enum):
	OK = 'OK'
	CONTINUE = 'CONT'
	ERR = 'ERR'

class ISC_REQ(enum.IntFlag):
	DELEGATE = 1
	MUTUAL_AUTH = 2
	REPLAY_DETECT = 4
	SEQUENCE_DETECT = 8
	CONFIDENTIALITY = 16
	USE_SESSION_KEY = 32
	PROMPT_FOR_CREDS = 64
	USE_SUPPLIED_CREDS = 128
	ALLOCATE_MEMORY = 256
	USE_DCE_STYLE = 512
	DATAGRAM = 1024
	CONNECTION = 2048
	CALL_LEVEL = 4096
	FRAGMENT_SUPPLIED = 8192
	EXTENDED_ERROR = 16384
	STREAM = 32768
	INTEGRITY = 65536
	IDENTIFY = 131072
	NULL_SESSION = 262144
	MANUAL_CRED_VALIDATION = 524288
	RESERVED1 = 1048576
	FRAGMENT_TO_FIT = 2097152
	HTTP = 0x10000000

class SEC_E(enum.Enum):
	OK = 0x00000000 
	CONTINUE_NEEDED = 0x00090312 
	INSUFFICIENT_MEMORY = 0x80090300 #Not enough memory is available to complete this request.
	INVALID_HANDLE = 0x80090301 #The handle specified is invalid.
	UNSUPPORTED_FUNCTION = 0x80090302 #The function requested is not supported.
	TARGET_UNKNOWN = 0x80090303 #The specified target is unknown or unreachable.
	INTERNAL_ERROR = 0x80090304 #The Local Security Authority (LSA) cannot be contacted.
	SECPKG_NOT_FOUND = 0x80090305  #The requested security package does not exist.
	NOT_OWNER = 0x80090306  #The caller is not the owner of the desired credentials.
	CANNOT_INSTALL = 0x80090307  #The security package failed to initialize and cannot be installed.
	INVALID_TOKEN = 0x80090308  #The token supplied to the function is invalid.
	CANNOT_PACK = 0x80090309  #The security package is not able to marshal the logon buffer, so the logon attempt has failed.
	QOP_NOT_SUPPORTED = 0x8009030A  #The per-message quality of protection is not supported by the security package.
	NO_IMPERSONATION = 0x8009030B  #The security context does not allow impersonation of the client.
	LOGON_DENIED = 0x8009030C  #The logon attempt failed.
	UNKNOWN_CREDENTIALS = 0x8009030D  #The credentials supplied to the package were not recognized.
	NO_CREDENTIALS = 0x8009030E  #No credentials are available in the security package.
	MESSAGE_ALTERED = 0x8009030F  #The message or signature supplied for verification has been altered.
	OUT_OF_SEQUENCE = 0x80090310  #The message supplied for verification is out of sequence.
	NO_AUTHENTICATING_AUTHORITY = 0x80090311  #No authority could be contacted for authentication.
	BAD_PKGID = 0x80090316  #The requested security package does not exist.
	CONTEXT_EXPIRED = 0x80090317  #The context has expired and can no longer be used.
	INCOMPLETE_MESSAGE = 0x80090318  #The supplied message is incomplete. The signature was not verified.
	INCOMPLETE_CREDENTIALS = 0x80090320  #The credentials supplied were not complete and could not be verified. The context could not be initialized.
	BUFFER_TOO_SMALL = 0x80090321  #The buffers supplied to a function was too small.
	WRONG_PRINCIPAL = 0x80090322  #The target principal name is incorrect.
	TIME_SKEW = 0x80090324  #The clocks on the client and server machines are skewed.
	UNTRUSTED_ROOT = 0x80090325  #The certificate chain was issued by an authority that is not trusted.
	ILLEGAL_MESSAGE = 0x80090326  #The message received was unexpected or badly formatted.
	CERT_UNKNOWN = 0x80090327  #An unknown error occurred while processing the certificate.
	CERT_EXPIRED = 0x80090328  # The received certificate has expired.
	ENCRYPT_FAILURE = 0x80090329  #The specified data could not be encrypted.
	DECRYPT_FAILURE = 0x80090330  #The specified data could not be decrypted.
	ALGORITHM_MISMATCH = 0x80090331  #The client and server cannot communicate because they do not possess a common algorithm.
	SECURITY_QOS_FAILED = 0x80090332  #The security context could not be established due to a failure in the requested quality of service (for example, mutual authentication or delegation).
	UNFINISHED_CONTEXT_DELETED = 0x80090333  #A security context was deleted before the context was completed. This is considered a logon failure.
	NO_TGT_REPLY = 0x80090334  #The client is trying to negotiate a context and the server requires user-to-user but did not send a ticket granting ticket (TGT) reply.
	NO_IP_ADDRESSES = 0x80090335  #Unable to accomplish the requested task because the local machine does not have an IP addresses.
	WRONG_CREDENTIAL_HANDLE = 0x80090336  #The supplied credential handle does not match the credential associated with the security context.
	CRYPTO_SYSTEM_INVALID = 0x80090337  #The cryptographic system or checksum function is invalid because a required function is unavailable.
	MAX_REFERRALS_EXCEEDED = 0x80090338  #The number of maximum ticket referrals has been exceeded.
	MUST_BE_KDC = 0x80090339  #The local machine must be a Kerberos domain controller (KDC), and it is not.
	STRONG_CRYPTO_NOT_SUPPORTED = 0x8009033A  #The other end of the security negotiation requires strong cryptographics, but it is not supported on the local machine.
	TOO_MANY_PRINCIPALS = 0x8009033B  #The KDC reply contained more than one principal name.
	NO_PA_DATA = 0x8009033C  #Expected to find PA data for a hint of what etype to use, but it was not found.
	PKINIT_NAME_MISMATCH = 0x8009033D  #The client certificate does not contain a valid user principal name (UPN), or does not match the client name in the logon request. Contact your administrator.
	SMARTCARD_LOGON_REQUIRED = 0x8009033E  #Smart card logon is required and was not used.
	SHUTDOWN_IN_PROGRESS = 0x8009033F  #A system shutdown is in progress.
	KDC_INVALID_REQUEST = 0x80090340  #An invalid request was sent to the KDC.
	KDC_UNABLE_TO_REFER = 0x80090341  #The KDC was unable to generate a referral for the service requested.
	KDC_UNKNOWN_ETYPE = 0x80090342  #The encryption type requested is not supported by the KDC.
	UNSUPPORTED_PREAUTH = 0x80090343  #An unsupported pre-authentication mechanism was presented to the Kerberos package.
	DELEGATION_REQUIRED = 0x80090345  #The requested operation cannot be completed. The computer must be trusted for delegation, and the current user account must be configured to allow delegation.
	BAD_BINDINGS = 0x80090346  #Client's supplied Security Support Provider Interface (SSPI) channel bindings were incorrect.
	MULTIPLE_ACCOUNTS = 0x80090347  #The received certificate was mapped to multiple accounts.
	NO_KERB_KEY = 0x80090348  #No Kerberos key was found.
	CERT_WRONG_USAGE = 0x80090349  #The certificate is not valid for the requested usage.
	DOWNGRADE_DETECTED = 0x80090350  #The system detected a possible attempt to compromise security. Ensure that you can contact the server that authenticated you.
	SMARTCARD_CERT_REVOKED = 0x80090351  #The smart card certificate used for authentication has been revoked. Contact your system administrator. The event log might contain additional information.
	ISSUING_CA_UNTRUSTED = 0x80090352  #An untrusted certification authority (CA) was detected while processing the smart card certificate used for authentication. Contact your system administrator.
	REVOCATION_OFFLINE_C = 0x80090353  #The revocation status of the smart card certificate used for authentication could not be determined. Contact your system administrator.
	PKINIT_CLIENT_FAILURE = 0x80090354  #The smart card certificate used for authentication was not trusted. Contact your system administrator.
	SMARTCARD_CERT_EXPIRED = 0x80090355  #The smart card certificate used for authentication has expired. Contact your system administrator.
	NO_S4U_PROT_SUPPORT = 0x80090356  #The Kerberos subsystem encountered an error. A service for user protocol requests was made against a domain controller that does not support services for users.
	CROSSREALM_DELEGATION_FAILURE = 0x80090357  #An attempt was made by this server to make a Kerberos-constrained delegation request for a target outside the server's realm. This is not supported and indicates a misconfiguration on this server's allowed-to-delegate-to list. Contact your administrator.
	REVOCATION_OFFLINE_KDC = 0x80090358  #The revocation status of the domain controller certificate used for smart card authentication could not be determined. The system event log contains additional information. Contact your system administrator.
	ISSUING_CA_UNTRUSTED_KDC = 0x80090359  #An untrusted CA was detected while processing the domain controller certificate used for authentication. The system event log contains additional information. Contact your system administrator.
	KDC_CERT_EXPIRED = 0x8009035A  #The domain controller certificate used for smart card logon has expired. Contact your system administrator with the contents of your system event log.
	KDC_CERT_REVOKED = 0x8009035B  #The domain controller certificate used for smart card logon has been revoked. Contact your system administrator with the contents of your system event log.
	INVALID_PARAMETER = 0x8009035D  #One or more of the parameters passed to the function were invalid.
	DELEGATION_POLICY = 0x8009035E  #The client policy does not allow credential delegation to the target server.
	POLICY_NLTM_ONLY = 0x8009035F  #The client policy does not allow credential delegation to the target server with NLTM only authentication.
	RENEGOTIATE = 590625
	COMPLETE_AND_CONTINUE = 590612
	COMPLETE_NEEDED = 590611
	#INCOMPLETE_CREDENTIALS = 590624

class SECPKG_CRED(enum.IntFlag):
	AUTOLOGON_RESTRICTED = 0x00000010 	#The security does not use default logon credentials or credentials from Credential Manager.
										#This value is supported only by the Negotiate security package.
										#Windows Server 2008, Windows Vista, Windows Server 2003 and Windows XP:  This value is not supported.

	BOTH = 3							#Validate an incoming credential or use a local credential to prepare an outgoing token. This flag enables both other flags. This flag is not valid with the Digest and Schannel SSPs.
	INBOUND = 1							#Validate an incoming server credential. Inbound credentials might be validated by using an authenticating authority when InitializeSecurityContext (General) or AcceptSecurityContext (General) is called. If such an authority is not available, the function will fail and return SEC_E_NO_AUTHENTICATING_AUTHORITY. Validation is package specific.
	OUTBOUND = 2						#Allow a local client credential to prepare an outgoing token.
	PROCESS_POLICY_ONLY = 0x00000020 	#The function processes server policy and returns SEC_E_NO_CREDENTIALS, indicating that the application should prompt for credentials.
										#This value is supported only by the Negotiate security package.
										#Windows Server 2008, Windows Vista, Windows Server 2003 and Windows XP:  This value is not supported.

# https://docs.microsoft.com/en-us/windows/desktop/api/sspi/ns-sspi-_secbuffer
class SECBUFFER_TYPE(enum.Enum):
	SECBUFFER_ATTRMASK = 4026531840 #The buffer contains a bitmask for a SECBUFFER_READONLY_WITH_CHECKSUM buffer.
	
	SECBUFFER_EMPTY = 0 #This is a placeholder in the buffer array. The caller can supply several such entries in the array, and the security package can return information in them. For more information, see SSPI Context Semantics.
	SECBUFFER_DATA = 1 #The buffer contains common data. The security package can read and write this data, for example, to encrypt some or all of it.
	SECBUFFER_TOKEN = 2 #The buffer contains the security token portion of the message. This is read-only for input parameters or read/write for output parameters.
	SECBUFFER_PKG_PARAMS = 3 #These are transport-to-package–specific parameters. For example, the NetWare redirector may supply the server object identifier, while DCE RPC can supply an association UUID, and so on.
	SECBUFFER_MISSING = 4 #The security package uses this value to indicate the number of missing bytes in a particular message. The pvBuffer member is ignored in this type.
	SECBUFFER_EXTRA = 5 #The security package uses this value to indicate the number of extra or unprocessed bytes in a message.
	SECBUFFER_STREAM_TRAILER = 6 #The buffer contains a protocol-specific trailer for a particular record. It is not usually of interest to callers.
	SECBUFFER_STREAM_HEADER = 7 #The buffer contains a protocol-specific header for a particular record. It is not usually of interest to callers.
	SECBUFFER_NEGOTIATION_INFO = 8
	SECBUFFER_PADDING = 9 
	SECBUFFER_STREAM = 10
	SECBUFFER_MECHLIST = 11 #The buffer contains a protocol-specific list of object identifiers (OIDs). It is not usually of interest to callers.
	SECBUFFER_MECHLIST_SIGNATURE = 12 #The buffer contains a signature of a SECBUFFER_MECHLIST buffer. It is not usually of interest to callers.
	SECBUFFER_TARGET = 13 #This flag is reserved. Do not use it.
	SECBUFFER_CHANNEL_BINDINGS = 14  #	The buffer contains channel binding information.
	SECBUFFER_CHANGE_PASS_RESPONSE = 15 #The buffer contains a DOMAIN_PASSWORD_INFORMATION structure.
	SECBUFFER_TARGET_HOST = 16 #The buffer specifies the service principal name (SPN) of the target.
								#This value is supported by the Digest security package when used with channel bindings.
								#Windows Server 2008, Windows Vista, Windows Server 2003 and Windows XP:  This value is not supported.
	SECBUFFER_ALERT = 17 #The buffer contains an alert message.
	SECBUFFER_APPLICATION_PROTOCOLS = 18 #The buffer contains a list of application protocol IDs, one list per application protocol negotiation extension type to be enabled.
	SECBUFFER_SRTP_PROTECTION_PROFILES = 19 #The buffer contains the list of SRTP protection profiles, in descending order of preference.
	SECBUFFER_SRTP_MASTER_KEY_IDENTIFIER = 20 #The buffer contains the SRTP master key identifier.
	SECBUFFER_TOKEN_BINDING = 21 #The buffer contains the supported token binding protocol version and key parameters, in descending order of preference.
	SECBUFFER_PRESHARED_KEY = 22 #The buffer contains the preshared key. The maximum allowed PSK buffer size is 256 bytes.
	SECBUFFER_PRESHARED_KEY_IDENTITY = 23 #The buffer contains the preshared key identity.
	SECBUFFER_DTLS_MTU = 24#The buffer contains the setting for the maximum transmission unit (MTU) size for DTLS only. The default value is 1096 and the valid configurable range is between 200 and 64*1024.
	"""
	In addition, BufferType can combine the following flags with any of the flags in the preceding table by using a bitwise-OR operation.
	Value 	Meaning
	SECBUFFER_READONLY
	2147483648 (0x80000000)
		The buffer is read-only with no checksum. This flag is intended for sending header information to the security package for computing the checksum. The package can read this buffer, but cannot modify it.
	SECBUFFER_READONLY_WITH_CHECKSUM
	268435456 (0x10000000)
		The buffer is read-only with a checksum
	"""

class SECPKG_ATTR(enum.Enum):
	SESSION_KEY = 9
	C_ACCESS_TOKEN = 0x80000012 #The pBuffer parameter contains a pointer to a SecPkgContext_AccessToken structure that specifies the access token for the current security context. This attribute is supported only on the server.
	C_FULL_ACCESS_TOKEN = 0x80000082 #The pBuffer parameter contains a pointer to a SecPkgContext_AccessToken structure that specifies the access token for the current security context. This attribute is supported only on the server.
	CERT_TRUST_STATUS = 0x80000084 #The pBuffer parameter contains a pointer to a CERT_TRUST_STATUS structure that specifies trust information about the certificate.This attribute is supported only on the client.
	CREDS = 0x80000080 # The pBuffer parameter contains a pointer to a SecPkgContext_ClientCreds structure that specifies client credentials. The client credentials can be either user name and password or user name and smart card PIN. This attribute is supported only on the server.
	CREDS_2 = 0x80000086 #The pBuffer parameter contains a pointer to a SecPkgContext_ClientCreds structure that specifies client credentials. If the client credential is user name and password, the buffer is a packed KERB_INTERACTIVE_LOGON structure. If the client credential is user name and smart card PIN, the buffer is a packed KERB_CERTIFICATE_LOGON structure. If the client credential is an online identity credential, the buffer is a marshaled SEC_WINNT_AUTH_IDENTITY_EX2 structure. This attribute is supported only on the CredSSP server. Windows Server 2008 R2, Windows 7, Windows Server 2008, Windows Vista, Windows Server 2003 and Windows XP:  This value is not supported.
	NEGOTIATION_PACKAGE = 0x80000081 #The pBuffer parameter contains a pointer to a SecPkgContext_PackageInfo structure that specifies the name of the authentication package negotiated by the Microsoft Negotiate provider.
	PACKAGE_INFO = 10 #The pBuffer parameter contains a pointer to a SecPkgContext_PackageInfostructure.Returns information on the SSP in use.
	SERVER_AUTH_FLAGS = 0x80000083 #The pBuffer parameter contains a pointer to a SecPkgContext_Flags structure that specifies information about the flags in the current security context. This attribute is supported only on the client.
	SIZES = 0x0 #The pBuffer parameter contains a pointer to a SecPkgContext_Sizes structure. Queries the sizes of the structures used in the per-message functions and authentication exchanges.
	SUBJECT_SECURITY_ATTRIBUTES = 124 #	The pBuffer parameter contains a pointer to a SecPkgContext_SubjectAttributes structure. This value returns information about the security attributes for the connection. This value is supported only on the CredSSP server. Windows Server 2008, Windows Vista, Windows Server 2003 and Windows XP:  This value is not supported.
	ENDPOINT_BINDINGS = 26

