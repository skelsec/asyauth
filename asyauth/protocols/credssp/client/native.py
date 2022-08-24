
import os
from asyauth import logger
from asyauth.protocols.spnego.client.native import SPNEGOClientNative
from asyauth.protocols.credssp.messages.asn1_structs import NegoDatas, \
	NegoData, TSRequest, TSRequest, TSPasswordCreds, TSCredentials, TSRemoteGuardCreds, \
	TSRemoteGuardPackageCred
from hashlib import sha256
from asn1crypto.x509 import Certificate
from asyauth.common.constants import asyauthSecret

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp/385a7489-d46b-464c-b224-f7340e308a5c

class CredSSPClientNative:
	def __init__(self, credential):
		self.credential = credential
		self.auth_ctx:SPNEGOClientNative = None
		self.cred = None
		self.version = 4 #ver 5 and 6 not working TODO
		self.nonce = os.urandom(32)
		self.__internal_auth_continue = True
		self.seqno = 0

	@staticmethod
	def certificate_to_pubkey(certdata):
		# credSSP auth requires knowledge of the server's public key
		cert = Certificate.load(certdata)
		return cert['tbs_certificate']['subject_public_key_info']['public_key'].dump()[5:] #why?

	def get_extra_info(self):
		return self.auth_ctx.get_extra_info()

	def get_active_credential(self):
		return self.auth_ctx.get_active_credential()

	async def authenticate(self, token, flags = None, certificate = None, spn = None, remote_credguard = False):
		try:
			# currently only SSPI supported

			if certificate is not None:
				pubkey = CredSSPClientNative.certificate_to_pubkey(certificate)
			
			if token is None:
				# initial auth
				returndata, self.__internal_auth_continue, err = await self.auth_ctx.authenticate(token, flags = flags, spn = spn)
				if err is not None:
					raise err
					
				negotoken = {
					'negoToken' : returndata
				}
				retoken = {
					'version' : self.version,
					'negoTokens' : NegoDatas([NegoData(negotoken)])
				}
				return TSRequest(retoken).dump(), True, None
			else:
				if self.__internal_auth_continue is True:
					tdata = TSRequest.load(token)
					if tdata.native['version'] < self.version:
						logger.debug('[CREDSSP] Server supports version %s which is smaller than our supported version %s' % (tdata.native['version'], self.version))
						self.version = tdata.native['version']
					if tdata.native['negoTokens'] is None:
						raise Exception('SSPI auth not supported by server')
					sspitoken = tdata.native['negoTokens'][0]['negoToken']
					returndata, self.__internal_auth_continue, err = await self.auth_ctx.authenticate(sspitoken, flags = flags, spn = spn)
					if err is not None:
						raise err
						
					negotoken = {
						'negoToken' : returndata
					}
					retoken = {
						'version' : self.version,
					}
					if returndata is not None:
						retoken['negoTokens'] = NegoDatas([NegoData(negotoken)])
						
						
					if self.__internal_auth_continue is False:
						self.seqno = self.auth_ctx.get_internal_seq() #spnego might increate a seq number when signing
						if self.version in [5,6]:
							ClientServerHashMagic = b"CredSSP Client-To-Server Binding Hash\x00"
							ClientServerHash = sha256(ClientServerHashMagic + self.nonce + pubkey).digest()
							sealedMessage, signature = await self.auth_ctx.encrypt(ClientServerHash, self.seqno)
							self.seqno += 1
							retoken['pubKeyAuth'] = signature+sealedMessage
							retoken['clientNonce'] = self.nonce
							
						elif self.version in [2,3,4]:
							sealedMessage, signature = await self.auth_ctx.encrypt(pubkey, self.seqno)
							self.seqno += 1
							retoken['pubKeyAuth'] = signature+sealedMessage
						
					return TSRequest(retoken).dump(), True, None
				else:
					# sub-level auth protocol finished, now for the other stuff
						
					# waiting for server to reply with the re-encrypted verification string + b'\x01'
					tdata = TSRequest.load(token).native
					if tdata['errorCode'] is not None:
						raise Exception('CredSSP - Server sent an error! Code: %s' % hex(tdata['errorCode'] & (2**32-1)))
					if tdata['pubKeyAuth'] is None:
						raise Exception('Missing pubKeyAuth')
					verification_data, _ = await self.auth_ctx.decrypt(tdata['pubKeyAuth'], 0)
					#print('DEC: %s' % verification_data)

					# at this point the verification should be implemented
					# TODO: maybe later...

					
					# sending credentials
					if remote_credguard is False:
						creds = {
							'domainName' : b'',
							'userName'   : b'',
							'password'   : b'',
						}
						cred = self.auth_ctx.get_active_credential()
						if cred.stype == asyauthSecret.PASSWORD:
							creds = {
								'domainName' : cred.domain.encode('utf-16-le'),
								'userName'   : cred.username.encode('utf-16-le'),
								'password'   : cred.secret.encode('utf-16-le'),
							}
								 
										
						res = TSPasswordCreds(creds)
						res = TSCredentials({'credType': 1, 'credentials': res.dump()})
						sealedMessage, signature = await self.auth_ctx.encrypt(res.dump(), self.seqno) #seq number must be incremented here..
						self.seqno += 1
						retoken = {
							'version' : self.version,
							'authInfo' : signature+sealedMessage
						}
						return TSRequest(retoken).dump(), False, None
					else:
						credBuffer = b''
						data = {
							'packageName' : 'KERBEROS'.encode('utf-16-le'), #dont forget the encoding!
							'credBuffer' : credBuffer
						}

						remcredguardcreds = TSRemoteGuardCreds({
							'logonCred' : TSRemoteGuardPackageCred(data),
							#'supplementalCreds' : [TSRemoteGuardPackageCred(xxxx)]
						})

						#print(remcredguardcreds)
						sealedMessage, signature = await self.auth_ctx.encrypt(remcredguardcreds.dump(), self.seqno) #seq number must be incremented here..
						self.seqno += 1
						retoken = {
							'version' : self.version,
							'authInfo' : signature+sealedMessage
						}
						return TSRequest(retoken).dump(), False, None						
		except Exception as e:
			return None, None, e