"""
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import os
import sys
import struct
import functools

from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.modes import GCM
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.hashes import SHA256

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from pmercury.protocols.protocol import Protocol
from pmercury.protocols.tls import TLS


class IQUIC(Protocol):
    VERSIONS = set([22,23,24])
    QUIC_VERSION_PARAMETERS = {
        22: {'salt': bytes.fromhex('7fbcdb0e7c66bbe9193a96cd21519ebd7a02644a')},
        23: {'salt': bytes.fromhex('c3eef712c72ebb5a11a7d2432bb46365bef9f502')},
        24: {'salt': bytes.fromhex('c3eef712c72ebb5a11a7d2432bb46365bef9f502')},
    }
    SAMPLE_SIZE = 16

    def __init__(self, fp_database=None, config=None):
        # populate fingerprint databases
        self.fp_db = None


    @staticmethod
    def proto_identify(data, offset, data_len):
        if (data[offset+1] != 0xff or
            data[offset+2] != 0x00 or
            data[offset+3] != 0x00 or
            data[offset+4] != 0x18):
            return False
        return True


    @staticmethod
    def kdf_tls13(secret, label, length):
        digest_type = SHA256()
        key = b''
        block = b''

        label = b'tls13 ' + label
        len_ = struct.pack('!H', length)
        label = b'%s%s%s%s' % (len_, struct.pack('B', len(label)), label, b'\x00')

        ind = 0
        while len(key) < length:
            ind += 1
            block = IQUIC.hmac(secret, digest_type, b'%s%s%s' % (block, label, struct.pack('B',ind)))
            key += block

        return bytearray(key[:length])


    @staticmethod
    def hmac(secret, digest_type, msg):
        tmp = HMAC(secret, digest_type, default_backend())
        tmp.update(msg)
        return tmp.finalize()


    @staticmethod
    def decrypt_packet(data):
        data = bytearray(data)
        data_len = len(data)
        offset = 0

        if data[4] not in IQUIC.VERSIONS:
            return None

        salt = IQUIC.QUIC_VERSION_PARAMETERS[data[4]]['salt']

        offset = 5
        dcid_len = data[offset]
        dcid = data[offset+1:offset+1+dcid_len]
        offset += 1+dcid_len
        if offset >= data_len:
            return None

        scid_len = data[offset]
        scid = data[offset+1:offset+1+scid_len]
        offset += 1+scid_len
        if offset >= data_len:
            return None

        token_len = data[offset]
        token = data[offset+1:offset+1+token_len]
        offset += 2+token_len
        if offset >= data_len:
            return None

        initial_secret = IQUIC.hmac(salt, SHA256(), dcid)
        client_initial_secret = IQUIC.kdf_tls13(initial_secret, b'client in', 32)
        key = IQUIC.kdf_tls13(client_initial_secret, b'quic key', 16)
        iv = IQUIC.kdf_tls13(client_initial_secret, b'quic iv', 12)
        hp = IQUIC.kdf_tls13(client_initial_secret, b'quic hp', 16)

        hp_encryptor = Cipher(algorithms.AES(hp), mode=modes.ECB(), backend=default_backend()).encryptor()
        buf = bytearray(31)
        sample = data[offset+4:offset+4+IQUIC.SAMPLE_SIZE]
        hp_encryptor.update_into(sample, buf)
        mask = buf[:5]

        data[0] ^= mask[0] & 0x0F
        pn_length = (data[0] & 0x03) + 1
        if offset+pn_length >= data_len:
            return None
        for i in range(pn_length):
            data[offset + i] ^= mask[1 + i]
        pn = data[offset:offset + pn_length]
        plain_header = data[:offset + pn_length]

        nonce = bytearray(len(iv) - pn_length) + bytearray(pn)
        for i in range(len(iv)):
            nonce[i] ^= iv[i]

        cipher = Cipher(AES(key), GCM(iv), backend=default_backend())
        payload = cipher.decryptor().update(bytes(data[offset + pn_length:]))

        return payload[4:]


    @staticmethod
    def fingerprint(data, offset, data_len):
        encrypted_data = data[offset:]
        decrypted_data = IQUIC.decrypt_packet(encrypted_data)
        if decrypted_data == None:
            return None, None
        if (decrypted_data[0] != 0x01 or
            decrypted_data[4] != 0x03 or
            decrypted_data[5] >  0x03):
            return None, None

        fp_, context = TLS.fingerprint(bytes.fromhex('1603030000') + decrypted_data, 0, len(decrypted_data)+5)
        if fp_ == None:
            return None, None

        quic_version = encrypted_data[1:5].hex()

        return '('+quic_version+')'+fp_, context


    def get_human_readable(self, fp_str_):
        return None


    def proc_identify(self, fp_str_, context_, dst_ip, dst_port, list_procs=5):
        return None

