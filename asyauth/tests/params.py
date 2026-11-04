import unittest
import os
import base64
from asyauth.common.credentials import UniCredential
from asyauth.common.constants import asyauthSecret
from asyauth.common.constants import asyauthProtocol
from asyauth.common.constants import asyauthSubProtocol
from minikerberos.common.creds import EncryptionType, Enctype

class TestURLNTLM(unittest.TestCase):
    def setUp(self):
        self.domain = 'TEST'
        self.username = 'testuser'
        self.secret = 'Passw0rd!1'
        self.stype = asyauthSecret.PASSWORD
        self.protocol = asyauthProtocol.NTLM
        self.subprotocol = asyauthSubProtocol.NATIVE

    def test_ntlm_plaintext(self):
        urls = ['smb2+ntlm-password://TEST\\testuser:Passw0rd!1@10.10.10.2',
            'smb2+ntlm-pass://TEST\\testuser:Passw0rd!1@10.10.10.2',
            'smb2+ntlm-pw://TEST\\testuser:Passw0rd!1@10.10.10.2',
            'smb2+NTLM-pw://TEST\\testuser:Passw0rd!1@10.10.10.2',
            'smb2+NTLM-PASSWORD://TEST\\testuser:Passw0rd!1@10.10.10.2',
        ]