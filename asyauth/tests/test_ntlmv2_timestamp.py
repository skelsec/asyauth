import datetime
import hashlib
import hmac
import unittest

from unicrypto.hashlib import md4

from asyauth.common.constants import asyauthSecret
from asyauth.common.credentials.ntlm import NTLMCredential
from asyauth.protocols.ntlm.creds_calc import netntlmv2
from asyauth.protocols.ntlm.structures.avpair import AVPairs, AVPAIRType
from asyauth.utils.timestamp import datetime2timestamp, timestamp2datetime


SERVER_CHALLENGE = bytes.fromhex('0123456789abcdef')
CLIENT_CHALLENGE = bytes.fromhex('aaaaaaaaaaaaaaaa')
# FILETIME with a non-zero 100ns digit, so it cannot survive a datetime round trip
SERVER_FILETIME = bytes.fromhex('13dce18e4d6cdd01')


def credential():
	return NTLMCredential('Password', 'User', 'Domain', asyauthSecret.PASSWORD)


def server_details(timestamp=SERVER_FILETIME):
	details = AVPairs()
	details[AVPAIRType.MsvAvNbDomainName] = 'Domain'
	details[AVPAIRType.MsvAvNbComputerName] = 'Server'
	if timestamp is not None:
		details[AVPAIRType.MsvAvTimestamp] = timestamp
	return details


def expected_nt_proof(blob):
	nt_hash = md4('Password'.encode('utf-16-le')).digest()
	ntowfv2 = hmac.new(nt_hash, 'USERDomain'.encode('utf-16-le'), hashlib.md5).digest()
	return hmac.new(ntowfv2, SERVER_CHALLENGE + blob, hashlib.md5).digest()


class TestNTLMv2Timestamp(unittest.TestCase):
	def test_filetime_precision_is_lost_through_datetime(self):
		self.assertNotEqual(datetime2timestamp(timestamp2datetime(SERVER_FILETIME)), SERVER_FILETIME)

	def test_server_msvavtimestamp_is_echoed_verbatim(self):
		creds = netntlmv2.construct(SERVER_CHALLENGE, CLIENT_CHALLENGE, server_details(), credential())
		cc = creds.NTResponse.ChallengeFromClinet

		self.assertEqual(cc.TimeStamp, SERVER_FILETIME)
		self.assertEqual(cc.to_bytes()[8:16], SERVER_FILETIME)
		self.assertEqual(creds.NTResponse.Response, expected_nt_proof(cc.to_bytes()))

	def test_explicit_timestamp_takes_precedence(self):
		explicit = datetime.datetime(2020, 1, 2, 3, 4, 5)
		creds = netntlmv2.construct(
			SERVER_CHALLENGE, CLIENT_CHALLENGE, server_details(), credential(), timestamp=explicit
		)

		self.assertEqual(creds.NTResponse.ChallengeFromClinet.TimeStamp, datetime2timestamp(explicit))

	def test_local_time_is_used_without_msvavtimestamp(self):
		before = datetime.datetime.utcnow()
		creds = netntlmv2.construct(SERVER_CHALLENGE, CLIENT_CHALLENGE, server_details(None), credential())
		after = datetime.datetime.utcnow()
		cc = creds.NTResponse.ChallengeFromClinet

		self.assertTrue(before <= timestamp2datetime(cc.TimeStamp) <= after)
		self.assertEqual(creds.NTResponse.Response, expected_nt_proof(cc.to_bytes()))


if __name__ == '__main__':
	unittest.main()
