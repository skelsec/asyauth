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
        urls = [
            'smb2+ntlm-password://TEST\\testuser:Passw0rd!1@10.10.10.2',
            'smb2+ntlm-pass://TEST\\testuser:Passw0rd!1@10.10.10.2',
            'smb2+ntlm-pw://TEST\\testuser:Passw0rd!1@10.10.10.2',
            'smb2+NTLM-pw://TEST\\testuser:Passw0rd!1@10.10.10.2',
            'smb2+NTLM-PASSWORD://TEST\\testuser:Passw0rd!1@10.10.10.2',
        ]
        
        for url in urls:
            cred = UniCredential.from_url(url)
            self.assertEqual(self.domain, cred.domain)
            self.assertEqual(self.username, cred.username)
            self.assertEqual(self.stype, cred.stype)
            self.assertEqual(self.protocol, cred.protocol)
            self.assertEqual(self.secret, cred.secret)
    
    def test_ntlm_plain_hex(self):
        urls = [
            'smb2+ntlm-pwhex://TEST\\testuser:50617373773072642131@10.10.10.2',
        ]
        
        for url in urls:
            cred = UniCredential.from_url(url)
            self.assertEqual(self.domain, cred.domain)
            self.assertEqual(self.username, cred.username)
            self.assertEqual(self.stype, cred.stype)
            self.assertEqual(self.protocol, cred.protocol)
            self.assertEqual(self.secret, cred.secret.decode())


    def test_ntlm_plain_b64(self):
        urls = [
            'smb2+ntlm-pwb64://TEST\\testuser:UGFzc3cwcmQhMQ==@10.10.10.2',
        ]
        
        for url in urls:
            cred = UniCredential.from_url(url)
            self.assertEqual(self.domain, cred.domain)
            self.assertEqual(self.username, cred.username)
            self.assertEqual(self.stype, cred.stype)
            self.assertEqual(self.protocol, cred.protocol)
            self.assertEqual(self.secret, cred.secret.decode())

    def test_ntlm_nt(self):
        urls = [
            'smb2+ntlm-nt://TEST\\testuser:f8963568a1ec62a3161d9d6449baba93@10.10.10.2',
        ]
        
        for url in urls:
            cred = UniCredential.from_url(url)
            self.assertEqual(self.domain, cred.domain)
            self.assertEqual(self.username, cred.username)
            self.assertEqual(asyauthSecret.NT, cred.stype)
            self.assertEqual(self.protocol, cred.protocol)
            self.assertEqual('f8963568a1ec62a3161d9d6449baba93', cred.secret)
    
    def test_ntlm_rc4(self):
        urls = [
            'smb2+ntlm-rc4://TEST\\testuser:f8963568a1ec62a3161d9d6449baba93@10.10.10.2',
        ]
        
        for url in urls:
            cred = UniCredential.from_url(url)
            self.assertEqual(self.domain, cred.domain)
            self.assertEqual(self.username, cred.username)
            self.assertEqual(asyauthSecret.NT, cred.stype)
            self.assertEqual(self.protocol, cred.protocol)
            self.assertEqual('f8963568a1ec62a3161d9d6449baba93', cred.secret)
    
    def test_ntlm_wrongsecret(self):
        urls = [
            'smb2+ntlm-aes://TEST\\testuser:f8963568a1ec62a3161d9d6449baba93@10.10.10.2',
            'smb2+ntlm-kirbi://TEST\\testuser:f8963568a1ec62a3161d9d6449baba93@10.10.10.2',
        ]
        
        for url in urls:
            with self.assertRaises(Exception):
                UniCredential.from_url(url)


class TestURLKerberos(unittest.TestCase):
    def setUp(self):
        self.domain = 'TEST'
        self.username = 'testuser'
        self.secret = 'Passw0rd!1'
        self.stype = asyauthSecret.PASSWORD
        self.protocol = asyauthProtocol.KERBEROS
        self.subprotocol = asyauthSubProtocol.NATIVE
        self.target = '10.10.10.2'
        self.kirbidata = 'doIE8DCCBOygAwIBBaEDAgEWooID/zCCA/thggP3MIID86ADAgEFoQobCFNFQy5DT1JQohgwFqADAgEBoQ8wDRsGa3JidGd0GwNTRUOjggPEMIIDwKADAgESoQMCAQKiggOyBIIDrk/UIoPXlNdYcKiu2Fj0+c9aHLTyb/HImTuvRvZjNH0Gk9Mwe5rtaREuhOIIvKWqsVeAVntFwZYCZX3mDNqGV9QsBEqlhvJ8wroG9thm76RrOiv3Y03EnWYUSiUFU6KZc2msvVZJfeCmkwQY61SOKlbYQ4XWX5lOlNw3Whm/d9r+I7XltHTFjm0yNbzP6gY+xO0jKburX020/hqsioFm9Ewx11eKU782dJp5FhZt/VkCTp0u5i5OV38ZfJhf7KaV0q8TvPkh5u9DCjDEkXJuocE9bJgs9AZO5aKyzso3C5BDS7Dtf9iyUsqrQkgSHuezNqKJ4Q1ondF4LC9Fxs5mtPfM2kB536vkrClOHKqoU3zxFMq73HDaM/IBW+aJbiDXDdsXq82kxSHc42lAPrkyCrSaAs30x1y1F3tJzFrUR3H6vtRbHkXaM1SJ45QPvCO/ojhmdel7MblXfUKmvP4kyqA/qNzBUIz5qQABZEseUb8dXVs1hYHYJ3lwOXk/jB2oyeDc1HKKE9VxpBrKuu+50qO7rF26t3YsVGvr3GNl5Mi9JKB5ggvI3WHgqdIbgGMOuYsrl4RqKfbEbUfoVuC8d56daxHxCBHNqxSYc2hJWkYUG3gL+BrB4duuDT3iii3kqCOjjh9KOJuw9O4dQ53axbMMY6eZ2ofwyJY6yBMBGPFO0l3bTi8UU00uebk0+k08zNNfs8pP/mw2ZaOFybuTX8xhGJInOiXymSZV/6CKp6Jt+QR98djMHi7RVdnRjTxIx7SNZPrkewgY6Dl14/rXDkNwv0vihN5domfdH7FFSqZQ62S4EMecSYX/e8lcEJLsS7H0eBsolbqG/kU95vueaBXy4q87dtgg1LBRJ8i7EV8IdzvoLK7bKmeaCOV7A0bz9aA/rCbHIEsc1BY5eRlw8Bw4DVqBK5hbZW5ErCVHwrqGb5COcGbn1pPdXPYv9SFyFmsTZ7GwImLe7kabaJu50SMuZrHS2j8Py9g40uQZQlzuKDtyr+k5uQYuvpWSp5ljrvoXOqOQTSRHh9p8GPdP3S1Lecuw4rmeppoQ7aAzMOz47cqa4wGja9oTc36/YxsDgHlklDrFOLLyGOTD+6lnGNKO/3sgaSp+TNpCmYrtuWwFHuxlY0RETSKhTJfL0XaBJUoXVmgBfAtmY/JWEYbZ8BT5QozEm6iQhtdSQhujTEiMdasG0I56K1FYndnx2Jz6NLZ2Dgo80gzQJuEA2AAtSylrArSt25mzjRWsPuaWpqOB3DCB2aADAgEAooHRBIHOfYHLMIHIoIHFMIHCMIG/oBswGaADAgGAoRIEEA5x07Ghq6urq6urq6urq6uhChsIU0VDLkNPUlCiFjAUoAMCAQGhDTALGwlhc3JlcHRlc3SjBQMDAFDBpBEYDzIwMjIxMTI0MDg1OTA0WqURGA8yMDIyMTEyNDA4NTkwNFqmERgPMjAyMjExMjUwODU5MDRapxEYDzIwMjIxMTI1MDg1OTA0WqgKGwhTRUMuQ09SUKkdMBugAwIBAaEUMBIbBmtyYnRndBsIU0VDLkNPUlA='
    
    def test_kerberos_plaintext(self):
        urls = [
            'smb2+kerberos-password://TEST\\testuser:Passw0rd!1@10.10.10.2/?dc=10.10.10.2',
            'smb2+kerberos-pass://TEST\\testuser:Passw0rd!1@10.10.10.2/?dc=10.10.10.2',
            'smb2+kerberos-pw://TEST\\testuser:Passw0rd!1@10.10.10.2/?dc=10.10.10.2',
            'smb2+KERBEROS-pw://TEST\\testuser:Passw0rd!1@10.10.10.2/?dc=10.10.10.2',
            'smb2+KERBEROS-PASSWORD://TEST\\testuser:Passw0rd!1@10.10.10.2/?dc=10.10.10.2',
        ]

        for url in urls:
            cred = UniCredential.from_url(url)
            self.assertEqual(self.domain, cred.domain)
            self.assertEqual(self.username, cred.username)
            self.assertEqual(self.stype, cred.stype)
            self.assertEqual(self.protocol, cred.protocol)
            self.assertEqual(self.secret, cred.secret)
            self.assertEqual(self.target, cred.target.ip)

    
    def test_kerberos_nodc(self):
        urls = [
            'smb2+kerberos-password://TEST\\testuser:Passw0rd!1@10.10.10.2',
            'smb2+kerberos-pass://TEST\\testuser:Passw0rd!1@10.10.10.2',
            'smb2+kerberos-pw://TEST\\testuser:Passw0rd!1@10.10.10.2',
            'smb2+KERBEROS-pw://TEST\\testuser:Passw0rd!1@10.10.10.2',
            'smb2+KERBEROS-PASSWORD://TEST\\testuser:Passw0rd!1@10.10.10.2',
        ]

        for url in urls:
            with self.assertRaises(Exception):
                UniCredential.from_url(url)

    def test_kerberos_plain_hex(self):
        urls = [
            'smb2+kerberos-pwhex://TEST\\testuser:50617373773072642131@10.10.10.2/?dc=10.10.10.2',
        ]
        
        for url in urls:
            cred = UniCredential.from_url(url)
            self.assertEqual(self.domain, cred.domain)
            self.assertEqual(self.username, cred.username)
            self.assertEqual(self.stype, cred.stype)
            self.assertEqual(self.protocol, cred.protocol)
            self.assertEqual(self.secret, cred.secret.decode())
            self.assertEqual(self.target, cred.target.ip)

    def test_kerberos_plain_b64(self):
        urls = [
            'smb2+kerberos-pwb64://TEST\\testuser:UGFzc3cwcmQhMQ==@10.10.10.2/?dc=10.10.10.2',
        ]
        
        for url in urls:
            cred = UniCredential.from_url(url)
            self.assertEqual(self.domain, cred.domain)
            self.assertEqual(self.username, cred.username)
            self.assertEqual(self.stype, cred.stype)
            self.assertEqual(self.protocol, cred.protocol)
            self.assertEqual(self.secret, cred.secret.decode())
            self.assertEqual(self.target, cred.target.ip)
    
    def test_kerberos_plain_b64(self):
        urls = [
            'smb2+kerberos-pwb64://TEST\\testuser:UGFzc3cwcmQhMQ==@10.10.10.2/?dc=10.10.10.2',
        ]
        
        for url in urls:
            cred = UniCredential.from_url(url)
            self.assertEqual(self.domain, cred.domain)
            self.assertEqual(self.username, cred.username)
            self.assertEqual(self.stype, cred.stype)
            self.assertEqual(self.protocol, cred.protocol)
            self.assertEqual(self.secret, cred.secret.decode())
            self.assertEqual(self.target, cred.target.ip)
    
    def test_kerberos_nt(self):
        urls = [
            'smb2+kerberos-nt://TEST\\testuser:f8963568a1ec62a3161d9d6449baba93@10.10.10.2/?dc=10.10.10.2',
        ]
        
        for url in urls:
            cred = UniCredential.from_url(url)
            self.assertEqual(self.domain, cred.domain)
            self.assertEqual(self.username, cred.username)
            self.assertEqual(asyauthSecret.RC4, cred.stype)
            self.assertEqual(self.protocol, cred.protocol)
            self.assertEqual('f8963568a1ec62a3161d9d6449baba93', cred.secret)
            self.assertEqual(self.target, cred.target.ip)
    
    def test_kerberos_rc4(self):
        urls = [
            'smb2+kerberos-rc4://TEST\\testuser:f8963568a1ec62a3161d9d6449baba93@10.10.10.2/?dc=10.10.10.2',
        ]
        
        for url in urls:
            cred = UniCredential.from_url(url)
            self.assertEqual(self.domain, cred.domain)
            self.assertEqual(self.username, cred.username)
            self.assertEqual(asyauthSecret.RC4, cred.stype)
            self.assertEqual(self.protocol, cred.protocol)
            self.assertEqual('f8963568a1ec62a3161d9d6449baba93', cred.secret)
            self.assertEqual(self.target, cred.target.ip)
    
    def test_kerberos_aes128(self):
        urls = [
            'smb2+kerberos-aes://TEST\\testuser:2511fa6466be6a454078e61e42e67b20@10.10.10.2/?dc=10.10.10.2',
        ]
        
        for url in urls:
            cred = UniCredential.from_url(url)
            self.assertEqual(self.domain, cred.domain)
            self.assertEqual(self.username, cred.username)
            self.assertEqual(asyauthSecret.AES, cred.stype)
            self.assertEqual(self.protocol, cred.protocol)
            self.assertEqual('2511fa6466be6a454078e61e42e67b20', cred.secret)
            self.assertEqual(self.target, cred.target.ip)

    def test_kerberos_aes256(self):
        urls = [
            'smb2+kerberos-aes://TEST\\testuser:b9f6819ef4e2fa19d607b66f716592d53d61d460965ee69e558a0544318ff24c@10.10.10.2/?dc=10.10.10.2',
        ]
        
        for url in urls:
            cred = UniCredential.from_url(url)
            self.assertEqual(self.domain, cred.domain)
            self.assertEqual(self.username, cred.username)
            self.assertEqual(asyauthSecret.AES, cred.stype)
            self.assertEqual(self.protocol, cred.protocol)
            self.assertEqual('b9f6819ef4e2fa19d607b66f716592d53d61d460965ee69e558a0544318ff24c', cred.secret)
            self.assertEqual(self.target, cred.target.ip)
    
    def test_kerberos_aes256_wrongkey(self):
        urls = [
            'smb2+kerberos-aes://TEST\\testuser:b9f6819ef4e2fa19d607b66f71659253d61d460965ee69e558a0544318ff24c@10.10.10.2/?dc=10.10.10.2',
        ]
        
        with self.assertRaises(Exception):
            for url in urls:
                cred = UniCredential.from_url(url)
                cred.to_ccred()
    
    def test_kerberos_kirbi(self):
        try:
            with open('test.kirbi', 'wb') as f:
                f.write(base64.b64decode(self.kirbidata.encode()))
            
            urls = [
                'smb2+kerberos-kirbi://TEST\\testuser:test.kirbi@10.10.10.2/?dc=10.10.10.2',
            ]
            
            for url in urls:
                cred = UniCredential.from_url(url)
                self.assertEqual(self.domain, cred.domain)
                self.assertEqual(self.username, cred.username)
                self.assertEqual(asyauthSecret.KIRBI, cred.stype)
                self.assertEqual(self.protocol, cred.protocol)
                self.assertEqual('test.kirbi', cred.secret)
                self.assertEqual(self.target, cred.target.ip)
                cred.to_ccred()
        finally:
            os.remove('test.kirbi')
    
    def test_kerberos_kirbi_nofile(self):
        urls = [
            'smb2+kerberos-kirbi://TEST\\testuser:nonexistent.kirbi@10.10.10.2/?dc=10.10.10.2',
        ]
        
        with self.assertRaises(FileNotFoundError):
            for url in urls:
                cred = UniCredential.from_url(url)
                cred.to_ccred()
    
    #def test_kerberos_kirbi_b64(self):
    #    urls = [
    #        'smb2+kerberos-kirbib64://TEST\\testuser:'+self.kirbidata+'@10.10.10.2/?dc=10.10.10.2',
    #    ]
    #    
    #    for url in urls:
    #        print(url)
    #        cred = UniCredential.from_url(url)
    #        cred.to_ccred()
    
    def test_kerberos_kirbi_hex(self):
        kd = base64.b64decode(self.kirbidata.encode()).hex()
        urls = [
            'smb2+kerberos-kirbihex://TEST\\testuser:'+kd+'@10.10.10.2/?dc=10.10.10.2',
        ]
        
        for url in urls:
            cred = UniCredential.from_url(url)
            cred.to_ccred()


if __name__ == '__main__':
    unittest.main()