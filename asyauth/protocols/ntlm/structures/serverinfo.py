
from asyauth.protocols.ntlm.structures.avpair import AVPAIRType
import datetime
import json

NTLMSERVERINFO_TSV_HDR = ['domainname', 'computername', 'dnsforestname', 'dnscomputername', 'dnsdomainname', 'local_time', 'os_major_version', 'os_minor_version', 'os_build', 'os_guess' ]


import datetime
import io

# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/2c57429b-fdd4-488f-b5fc-9e4cf020fcdf
class FILETIME:
	def __init__(self):
		self.dwLowDateTime = None
		self.dwHighDateTime = None
		
		self.datetime = None
	@staticmethod
	def from_bytes(data):
		return FILETIME.from_buffer(io.BytesIO(data))

	@staticmethod
	def from_datetime(dt):
		t = FILETIME()
		# Convert to Windows FILETIME: 100-nanosecond intervals since January 1, 1601 UTC
		# Unix epoch starts at January 1, 1970, so we add the difference
		unix_timestamp = int(dt.timestamp())
		# Convert to 100-nanosecond intervals and add offset from 1601 to 1970
		filetime_value = (unix_timestamp * 10000000) + 116444736000000000
		t.dwLowDateTime = filetime_value & 0xFFFFFFFF
		t.dwHighDateTime = (filetime_value >> 32) & 0xFFFFFFFF
		t.calc_dt()
		return t

	def to_bytes(self):
		if self.dwLowDateTime is None or self.dwHighDateTime is None:
			raise ValueError("FILETIME values cannot be None for serialization")
		return self.dwLowDateTime.to_bytes(4, 'little') + self.dwHighDateTime.to_bytes(4, 'little')
	
	def calc_dt(self):
		if self.dwHighDateTime == 4294967295 and self.dwLowDateTime == 4294967295:
			self.datetime = datetime.datetime(3000, 1, 1, 0, 0)
		else:
			ft = (self.dwHighDateTime << 32) + self.dwLowDateTime
			if ft == 0:
				self.datetime = datetime.datetime(1970, 1, 1, 0, 0)
			else:
				self.datetime = datetime.datetime.utcfromtimestamp((ft - 116444736000000000) / 10000000)
	
	@staticmethod
	def from_dict(d):
		t = FILETIME()
		t.dwLowDateTime = d['dwLowDateTime']
		t.dwHighDateTime = d['dwHighDateTime']
		t.calc_dt()
		return t

	@staticmethod
	def from_buffer(buff):
		t = FILETIME()
		t.dwLowDateTime = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		t.dwHighDateTime = int.from_bytes(buff.read(4), byteorder='little', signed = False)
		t.calc_dt()
		return t



class NTLMServerInfo:
	def __init__(self):
		self.domainname = None
		self.computername = None
		self.dnscomputername = None
		self.dnsdomainname = None
		self.local_time = None
		self.dnsforestname = None
		self.os_major_version = None
		self.os_minor_version = None
		self.os_build = None
		self.os_guess = None
		self.creds = None
	
	@staticmethod
	def from_challenge(challenge):
		si = NTLMServerInfo()
		ti = challenge.TargetInfo
		for k in ti:
			if k == AVPAIRType.MsvAvNbDomainName:
				si.domainname = ti[k]
			elif k == AVPAIRType.MsvAvNbComputerName:
				si.computername = ti[k]
			elif k == AVPAIRType.MsvAvDnsDomainName:
				si.dnsdomainname = ti[k]
			elif k == AVPAIRType.MsvAvDnsComputerName:
				si.dnscomputername = ti[k]
			elif k == AVPAIRType.MsvAvDnsTreeName:
				si.dnsforestname = ti[k]
			elif k == AVPAIRType.MsvAvTimestamp:
				if isinstance(ti[k], bytes):
					si.local_time = FILETIME.from_bytes(ti[k]).datetime
				elif isinstance(ti[k], datetime):
					si.local_time = ti[k]
		
		if challenge.Version is not None:
			if challenge.Version.ProductMajorVersion is not None:
				si.os_major_version = challenge.Version.ProductMajorVersion
			if challenge.Version.ProductMinorVersion is not None:
				si.os_minor_version = challenge.Version.ProductMinorVersion
			if challenge.Version.ProductBuild is not None:
				si.os_build = challenge.Version.ProductBuild
			if challenge.Version.WindowsProduct is not None:
				si.os_guess = challenge.Version.WindowsProduct
				
		return si

	def to_dict(self):
		t = {
			'domainname' : self.domainname,
			'computername' : self.computername,
			'dnscomputername' : self.dnscomputername,
			'dnsdomainname' : self.dnsdomainname,
			'local_time' : self.local_time,
			'dnsforestname' : self.dnsforestname,
			'os_build' : self.os_build,
			'os_guess' : self.os_guess,
			'os_major_version' : None,
			'os_minor_version' : None,
		}
		if self.os_major_version is not None:
			t['os_major_version'] = self.os_major_version.name
		if self.os_minor_version is not None:
			t['os_minor_version'] = self.os_minor_version.name
		if self.creds is not None:
			t['creds'] = self.creds.to_dict()
		return t

	def to_tsv(self, separator = '\t'):
		def vn(x):
			if x is None:
				return ''
			return str(x)

		d = self.to_dict()
		return separator.join([ vn(d[x]) for x in NTLMSERVERINFO_TSV_HDR])
		
	def __str__(self):
		t = '=== Server Info ====\r\n'
		for k in self.__dict__:
			t += '%s: %s\r\n' % (k, self.__dict__[k]) 
			
		return t

	def to_json(self):
		return json.dumps(self.to_dict())

	def to_grep(self):
		t  = ''
		t += '[domainname,%s]' % self.domainname
		t += '[computername,%s]' %  self.computername
		t += '[dnscomputername,%s]' %  self.dnscomputername
		t += '[dnsdomainname,%s]' %  self.dnsdomainname
		t += '[dnsforestname,%s]' %  self.dnsforestname
		t += '[os_build,%s]' %  self.os_build
		t += '[os_guess,%s]' %  self.os_guess
		if self.local_time is not None:
			t += '[local_time,%s]' %  self.local_time.isoformat()
		if self.os_major_version is not None:
			t += '[os_major,%s]' % self.os_major_version.value
		if self.os_minor_version is not None:
			t += '[os_minor,%s]' % self.os_minor_version.value
		
		return t