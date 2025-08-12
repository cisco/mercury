import json
import os
import unittest
from binascii import unhexlify

import mercury
from mercury_python_test_data import *



class TestMercuryPython(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        if os.path.exists('../../test/data/resources-test.tgz'):
            cls.libmerc = mercury.Mercury(do_analysis=True, resources=b'../../test/data/resources-test.tgz')
        else:
            cls.libmerc = mercury.Mercury(do_analysis=True, resources=b'test/data/resources-test.tgz')


    def test_certificate_parsing(self):
        cert_data = {
            'version': '02',
            'serial_number': '00eede6560cd35c0af02000000005971b7',
            'bits_in_signature': 2047
        }
        merc_cert_data = mercury.parse_cert(b64_cert)
        self.assertEqual(merc_cert_data['version'], cert_data['version'], f"Certificate version should be {cert_data['version']}")
        self.assertEqual(merc_cert_data['serial_number'], cert_data['serial_number'],
                         f"Certificate serial_number should be {cert_data['serial_number']}")
        self.assertEqual(merc_cert_data['bits_in_signature'], cert_data['bits_in_signature'],
                         f"Certificate bits_in_signature should be {cert_data['bits_in_signature']}")


    def test_dns_parsing(self):
        dns_data = {
            'response': {
                'id': 'edd5',
                'question': [{'name': 'live.github.com.'}],
                'authority': [{'name': 'github.com.'}]
            }
        }
        merc_dns_data = mercury.parse_dns(b64_dns)
        self.assertEqual(merc_dns_data['response']['id'], dns_data['response']['id'], f"DNS transaction id should be {dns_data['response']['id']}")
        self.assertEqual(merc_dns_data['response']['question'][0]['name'], dns_data['response']['question'][0]['name'],
                         f"DNS question name should be {dns_data['response']['question'][0]['name']}")
        self.assertEqual(merc_dns_data['response']['authority'][0]['name'], dns_data['response']['authority'][0]['name'],
                         f"DNS authority name should be {dns_data['response']['authority'][0]['name']}")


    def test_analysis(self):
        analysis_data = {
            'analysis': {
                "process": "firefox",
                "score": 1.0
            }
        }
        merc_analysis_data = TestMercuryPython.libmerc.analyze_packet(unhexlify(firefox_pkt))
        self.assertEqual(merc_analysis_data['analysis']['process'], analysis_data['analysis']['process'],
                         f"analysis process name should be {analysis_data['analysis']['process']}")
        self.assertEqual(merc_analysis_data['analysis']['score'], analysis_data['analysis']['score'],
                         f"analysis process score should be {analysis_data['analysis']['score']}")


    def test_tls_fingerprint(self):
        fingerprint_data = {
            'fingerprints': {
                'tls': 'tls/(0303)(130113031302c02bc02fcca9cca8c02cc030c00ac009c013c014009c009d002f0035000a)((0000)(0017)(ff01)(000a000e000c001d00170018001901000101)(000b00020100)(0023)(0010000e000c02683208687474702f312e31)(000500050100000000)(0033)(002b00050403040303)(000d0018001604030503060308040805080604010501060102030201)(002d00020101)(001c00024001)(0015))'
            }
        }
        merc_fingerprint_data = TestMercuryPython.libmerc.get_mercury_json(unhexlify(firefox_pkt))
        self.assertEqual(merc_fingerprint_data['fingerprints']['tls'], fingerprint_data['fingerprints']['tls'],
                         f"TLS fingerprint should be {fingerprint_data['fingerprints']['tls']}")


    def test_quic_fingerprint(self):
        fingerprint_data = {
            'fingerprints': {
                'quic': 'quic/(00000001)(0303)(0a0a130113021303)[(000500050100000000)(000a000c000a0a0a001d001700180019)(000d0018001604030804040105030203080508050501080606010201)(001000050003026833)(0012)(001b0003020001)(0029)(002b0005040a0a0304)(002d00020101)(0033)((0039)[(01)(04)(05)(06)(07)(08)(09)(0e)(0f)])(0a0a)(0a0a)]'
            }
        }
        merc_fingerprint_data = TestMercuryPython.libmerc.get_mercury_json(unhexlify(quic_pkt))
        self.assertEqual(merc_fingerprint_data['fingerprints']['quic'], fingerprint_data['fingerprints']['quic'],
                         f"TLS fingerprint should be {fingerprint_data['fingerprints']['quic']}")


    def test_ech_config(self):
        ech_config = {
            'version': 'fe0d',
            'hpke_key_config': {
                'config_id': 54,
                'kem': 'DHKEM_X25519_HKDF_SHA256'
            },
            'public_name': 'cloudflare-ech.com'
        }
        ech_config_json = mercury.parse_ech_config(ech_cfg_b64)
        self.assertEqual(ech_config_json['ech_config']['version'], ech_config['version'],
                         f"ECH version should be {ech_config['version']}")
        self.assertEqual(ech_config_json['ech_config']['hpke_key_config']['config_id'], ech_config['hpke_key_config']['config_id'],
                         f"ECH config_id should be {ech_config['hpke_key_config']['config_id']}")
        self.assertEqual(ech_config_json['ech_config']['hpke_key_config']['kem'], ech_config['hpke_key_config']['kem'],
                         f"ECH kem should be {ech_config['hpke_key_config']['kem']}")
        self.assertEqual(ech_config_json['ech_config']['public_name'], ech_config['public_name'],
                         f"ECH public_name should be {ech_config['public_name']}")


    def test_unlabeled_analysis_result(self):
        str_repr    = 'tls/1/(0303)(abcdef01)[(0000)]'
        dst_ip      = '173.37.145.84'
        server_name = 'www.cisco.com'
        dst_port    = 443

        cls_result = self.libmerc.perform_analysis_with_user_agent(str_repr, server_name, dst_ip, dst_port, '')
        self.assertEqual(cls_result['fingerprint_info']['status'], f"randomized",
                         f"Fingerprint should be randomized initially")
        self.assertEqual(cls_result['analysis']['attributes'][0]['name'], f"faketls",
                         f"FakeTLS should be the only attribute in the randomized case")

        cls_result = self.libmerc.perform_analysis_with_user_agent(str_repr, server_name, dst_ip, dst_port, '')
        self.assertEqual(cls_result['fingerprint_info']['status'], f"unlabled",
                         f"Fingerprint should be unlabeled")
        self.assertEqual(cls_result['analysis']['attributes'][0]['name'], f"faketls",
                         f"FakeTLS should be the only attribute in the unlabeled case")


if __name__ == '__main__':
    unittest.main()
