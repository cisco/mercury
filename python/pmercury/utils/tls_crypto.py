import os
import sys
import struct
from binascii import hexlify, unhexlify

# crypto primitive imports
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.modes import GCM, CBC
from cryptography.hazmat.primitives.hashes import SHA1, SHA256, SHA384, MD5, Hash
from cryptography.hazmat.primitives.ciphers.algorithms import AES, ARC4, TripleDES, Camellia, SEED

# constants
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from pmercury.utils.tls_constants import *


class TLS_CRYPTO:

    def __init__(self):
        self.cur_mode = None
        self.session_metadata = None
        self.tls_sequence = None
        self.tls13_handshake = None
        self.kdf = {}
        self.kdf['TLS 1.0'] = self.kdf_tls10
        self.kdf['TLS 1.1'] = self.kdf_tls11
        self.kdf['TLS 1.2'] = self.kdf_tls12
        self.kdf['TLS 1.3'] = self.kdf_tls13


    def kdf_tls10(self, cr, sr, secret, cipher_params, flow_key):
        if flow_key+self.cur_mode not in self.session_metadata:
            self.session_metadata[flow_key+self.cur_mode] = {}
        if 'cbc_initial_decrypt' not in self.session_metadata[flow_key+self.cur_mode]:
            self.session_metadata[flow_key+self.cur_mode]['cbc_initial_decrypt'] = 1
            fixed_iv_length = cipher_params['iv_length']
        else:
            fixed_iv_length = cipher_params['fixed_iv_length']
        label = b'key expansion'

        secret_md5 = secret[:len(secret)/2]
        secret_sha = secret[-len(secret)/2:]

        md5_material = b''
        cur_hash = self.hmac(secret_md5, MD5(), b'%s%s%s' % (label, sr, cr))
        for i in range(16):
            md5_material += self.hmac(secret_md5, MD5(), b'%s%s%s%s' % (cur_hash, label, sr, cr))
            cur_hash = self.hmac(secret_md5, MD5(), cur_hash)
        
        sha_material = b''
        cur_hash = self.hmac(secret_sha, SHA1(), b'%s%s%s' % (label, sr, cr))
        for i in range(16):
            sha_material += self.hmac(secret_sha, SHA1(), b'%s%s%s%s' % (cur_hash, label, sr, cr))
            cur_hash = self.hmac(secret_sha, SHA1(), cur_hash)

        output = b''
        for i in range(min(len(md5_material),len(sha_material))):
            output += chr(ord(md5_material[i]) ^ ord(sha_material[i]))

        key_material_lengths = [cipher_params['mac_key_length']]*2 + \
                               [cipher_params['enc_key_length']]*2 + \
                               [fixed_iv_length]*2

        offset = 0
        key_material = []
        for l in key_material_lengths:
            key_material.append(output[offset:offset+l])
            offset += l

        return key_material


    def kdf_tls11(self, cr, sr, secret, cipher_params, flow_key):
        label = b'key expansion'

        secret_md5 = secret[:len(secret)/2]
        secret_sha = secret[-len(secret)/2:]

        md5_material = b''
        cur_hash = self.hmac(secret_md5, MD5(), b'%s%s%s' % (label, sr, cr))
        for i in range(16):
            md5_material += self.hmac(secret_md5, MD5(), b'%s%s%s%s' % (cur_hash, label, sr, cr))
            cur_hash = self.hmac(secret_md5, MD5(), cur_hash)
        
        sha_material = b''
        cur_hash = self.hmac(secret_sha, SHA1(), b'%s%s%s' % (label, sr, cr))
        for i in range(16):
            sha_material += self.hmac(secret_sha, SHA1(), b'%s%s%s%s' % (cur_hash, label, sr, cr))
            cur_hash = self.hmac(secret_sha, SHA1(), cur_hash)

        output = b''
        for i in range(min(len(md5_material),len(sha_material))):
            output += chr(ord(md5_material[i]) ^ ord(sha_material[i]))

        key_material_lengths = [cipher_params['mac_key_length']]*2 + \
                               [cipher_params['enc_key_length']]*2 + \
                               [cipher_params['fixed_iv_length']]*2

        offset = 0
        key_material = []
        for l in key_material_lengths:
            key_material.append(output[offset:offset+l])
            offset += l

        return key_material


    def kdf_tls12(self, cr, sr, secret, cipher_params, flow_key):
        label = b'key expansion'
        digest_type = cipher_params['prf']()

        cur_hash = self.hmac(secret, digest_type, b'%s%s%s' % (label, sr, cr))
        output = b''
        for i in range(16):
            output += self.hmac(secret, digest_type, b'%s%s%s%s' % (cur_hash, label, sr, cr))
            cur_hash = self.hmac(secret, digest_type, cur_hash)

        key_material_lengths = [cipher_params['mac_key_length']]*2 + \
                               [cipher_params['enc_key_length']]*2 + \
                               [cipher_params['fixed_iv_length']]*2
        offset = 0
        key_material = []
        for l in key_material_lengths:
            key_material.append(output[offset:offset+l])
            offset += l

        return key_material


    def kdf_tls13(self, secret, label, length, cipher_params, flow_key):
        digest_type = cipher_params['prf']()
        key = b''
        block = b''

        ind = 0
        while len(key) < length:
            ind += 1
            block = self.hmac(secret, digest_type, b'%s%s%s' % (block, label, struct.pack('B',ind)))
            key += block

        return key[:length]


    def hmac(self, secret, digest_type, msg):
        tmp = HMAC(secret, digest_type, default_backend())
        tmp.update(msg)
        return tmp.finalize()


    def hash_(self, digest_type, msg):
        tmp = Hash(digest_type, default_backend())
        tmp.update(msg)
        return tmp.finalize()


    def get_secret(self, client_random, secrets, cur_flow_key):
        secret = None
        if client_random not in secrets:
            return None

        if not self.session_metadata['version'].startswith('TLS 1.3'):
            secret = unhexlify(secrets[client_random]['master_secret'])

        # find appropriate master secret
        if cur_flow_key not in self.tls13_handshake:
            self.tls13_handshake[cur_flow_key] = True
        if self.cur_mode == 'client' and self.tls13_handshake[cur_flow_key] == True and \
           'client_handshake_secret' in secrets[client_random]:
            secret = unhexlify(secrets[client_random]['client_handshake_secret'])
        elif self.cur_mode == 'server' and self.tls13_handshake[cur_flow_key] == True and \
           'server_handshake_secret' in secrets[client_random]:
            secret = unhexlify(secrets[client_random]['server_handshake_secret'])
        elif self.cur_mode == 'client' and self.tls13_handshake[cur_flow_key] == False and \
             'client_traffic_secret' in secrets[client_random]:
            secret = unhexlify(secrets[client_random]['client_traffic_secret'])
        elif self.cur_mode == 'server' and self.tls13_handshake[cur_flow_key] == False and \
             'server_traffic_secret' in secrets[client_random]:
            secret = unhexlify(secrets[client_random]['server_traffic_secret'])

        return secret


    def get_explicit_material(self, flow_key, data, cipher_params):
        enc = None
        iv = None

        if self.session_metadata['version'] == 'TLS 1.0':
            enc = data
            if cipher_params['mode'] == CBC:
                if flow_key+self.cur_mode not in self.session_metadata or \
                   'cbc_initial_decrypt' not in self.session_metadata[flow_key+self.cur_mode] or \
                   'cur_iv' not in self.session_metadata[flow_key+self.cur_mode]:
                    iv = b''
                else:
                    iv = self.session_metadata[flow_key+self.cur_mode]['cur_iv']
        elif self.session_metadata['version'] in ['TLS 1.1','TLS 1.2']:
            enc = data[cipher_params['iv_length']:]
            iv = data[:cipher_params['iv_length']]
        elif self.session_metadata['version'].startswith('TLS 1.3'):
            enc = data
            iv = b''

        return enc, iv


    def get_implicit_material(self, client_random, server_random, master_secret, \
                              cipher_params, flow_key, explicit_iv):
        key = None
        iv = None

        if self.session_metadata['version'] in ['SSL 3.0','TLS 1.0','TLS 1.1','TLS 1.2']:
            c_mac_key, s_mac_key, c_key, s_key, c_iv, s_iv = \
                self.kdf[self.session_metadata['version']](client_random, server_random, \
                                                           master_secret, cipher_params, flow_key)
            if self.cur_mode == 'client':
                key = c_key
                iv = c_iv + explicit_iv
            else:
                key = s_key
                iv = s_iv + explicit_iv
        elif self.session_metadata['version'].startswith('TLS 1.3'):
            cur_flow_key = flow_key + self.cur_mode
            label_str = b''
            if self.session_metadata['version'] == 'TLS 1.3' or self.session_metadata['version'] == 'TLS 1.3 (draft 20)':
                label_str = b'tls13 '
            else:
                label_str = b'TLS 1.3, '
            tmp_label = label_str + b'key'
            len_ = struct.pack(b'!H', cipher_params['enc_key_length'])
            tmp_label = b'%s%s%s%s' % (len_, struct.pack(b'B', len(tmp_label)), tmp_label, b'\x00')
            key = self.kdf_tls13(master_secret, tmp_label, cipher_params['enc_key_length'], \
                                 cipher_params, flow_key)

            tmp_label = label_str + b'iv'
            len_ = struct.pack(b'!H', cipher_params['iv_length'])
            tmp_label = b'%s%s%s%s' % (len_, struct.pack(b'B', len(tmp_label)), tmp_label, b'\x00')
            implicit_iv = self.kdf_tls13(master_secret, tmp_label, cipher_params['iv_length'], \
                                         cipher_params, flow_key)
            
            # calculate nonce
            iv2 = struct.pack(b'!Q', self.tls_sequence[cur_flow_key]).rjust(len(implicit_iv), b'\x00')
            iv = b''.join([struct.pack(b'B', v ^ implicit_iv[i]) for i, v in enumerate(iv2)])

        return key, iv


    # strip MAC/AEAD/Padding
    def get_data(self, result, flow_key, cipher_params, encrypted_data):
        padding_length = 0

        # strip padding
        if self.session_metadata['version'].startswith('TLS 1.3'):
            for i in range(len(result)-1,-1,-1):
                if result[i] != b'\x00':
                    break
                padding_length += 1
            result = result[:-padding_length-1]
        else:
            if cipher_params['mode'] == CBC:
                padding_length = int(hexlify(result[-1:]),16)
                if len(result) < padding_length+1:
                    padding_length = 0
                else:
                    for i in range(1,padding_length+1):
                        if int(hexlify(result[-(i+1):-i]),16) != padding_length:
                            padding_length = 0
                            break
                if padding_length != 0:
                    padding_length += 1
                    result = result[:-padding_length]

                # set up IV for TLS 1.0
                if self.session_metadata['version'] == 'TLS 1.0':
                    if flow_key+self.cur_mode not in self.session_metadata:
                        self.session_metadata[flow_key+self.cur_mode] = {}
                    self.session_metadata[flow_key+self.cur_mode]['cur_iv'] = encrypted_data[-cipher_params['iv_length']:]

        # strip AEAD/MAC
        auth_length = 0
        if cipher_params['mode'] == GCM:
            if cipher_params['enc_key_length'] == 32:
                result = result[:-16]
            elif cipher_params['enc_key_length'] == 16:
                result = result
            auth_length = cipher_params['enc_key_length']
        elif cipher_params['mac_key_length'] > 0:
            result = result[:-cipher_params['mac_key_length']]
            auth_length = cipher_params['mac_key_length']

        return result, padding_length, auth_length


    # get encrypted data and crypto parameters, output plaintext
    def get_plaintext(self, data, cipher_params, key, iv, flow_key):
        if cipher_params['cipher'] == AES:
            if cipher_params['mode'] == CBC:
                decryptor = Cipher(cipher_params['cipher'](key), \
                                   cipher_params['mode'](iv), \
                                   default_backend()).decryptor()
            if cipher_params['mode'] == GCM:
                if len(data[-16:]) < 16:
                    return None
                decryptor = Cipher(cipher_params['cipher'](key), \
                                   cipher_params['mode'](iv,data[-16:]), \
                                   default_backend()).decryptor()
        elif cipher_params['cipher'] == ARC4:
            if flow_key+self.cur_mode not in self.session_metadata:
                self.session_metadata[flow_key+self.cur_mode] = {}
            if 'decryptor' not in self.session_metadata[flow_key+self.cur_mode]:
                self.session_metadata[flow_key+self.cur_mode]['decryptor'] = \
                    decryptor = Cipher(cipher_params['cipher'](key), \
                                       None,
                                       default_backend()).decryptor()
            decryptor = self.session_metadata[flow_key+self.cur_mode]['decryptor']
        elif cipher_params['cipher'] == TripleDES:
                decryptor = Cipher(cipher_params['cipher'](key), \
                                   cipher_params['mode'](iv), \
                                   default_backend()).decryptor()
        elif cipher_params['cipher'] == Camellia:
                decryptor = Cipher(cipher_params['cipher'](key), \
                                   cipher_params['mode'](iv), \
                                   default_backend()).decryptor()
        elif cipher_params['cipher'] == SEED:
                decryptor = Cipher(cipher_params['cipher'](key), \
                                   cipher_params['mode'](iv), \
                                   default_backend()).decryptor()
        else:
            print('%s Not Supported' % cipher_params['cipher'])
            return None

        return decryptor.update(data)


    # Main decrypt function
    def decrypt(self, data, flow_key, cur_mode, session_metadata, tls_sequence, secrets, tls13_handshake):
        self.cur_mode = cur_mode
        self.session_metadata = session_metadata
        self.tls_sequence = tls_sequence
        self.tls13_handshake = tls13_handshake

        if 'selected_cipher_suite' not in self.session_metadata or 'client_random' not in self.session_metadata \
           or 'server_random' not in self.session_metadata:
            return None, None, None
        cur_flow_key = flow_key + self.cur_mode
        if self.session_metadata['selected_cipher_suite'] not in TLS_CIPHER_SUITES:
            print('NYI:\t' + self.session_metadata['selected_cipher_suite'])
            return None, None, None

        cipher_params = TLS_CIPHER_SUITES[self.session_metadata['selected_cipher_suite']]
        client_random = self.session_metadata['client_random']
        server_random = self.session_metadata['server_random']

        # set initial sequence number for decryption
        if cur_flow_key not in self.tls_sequence:
            self.tls_sequence[cur_flow_key] = 0

        # get master secret, varies for TLS 1.3
        master_secret = self.get_secret(client_random, secrets, cur_flow_key)
        if master_secret == None:
            return None, None, None

        # get encrypted data and (if necessary) explicit iv
        encrypted_data, explicit_iv = \
            self.get_explicit_material(flow_key, data, cipher_params)
        if encrypted_data == None or explicit_iv == None:
            return None, None, None

        # get encryption key and implicit iv
        key, iv = self.get_implicit_material(unhexlify(client_random), \
                        unhexlify(server_random), master_secret, cipher_params, \
                        flow_key, explicit_iv)

        # decrypt encrypted text
        result = self.get_plaintext(encrypted_data, cipher_params, key, iv, flow_key)
        if result == None:
            return None, None, None

        # determine if padding is used
        result, padding_length, auth_length = self.get_data(result, flow_key, \
                                               cipher_params, encrypted_data)

        # update sequence number
        self.tls_sequence[cur_flow_key] += 1

        return result, padding_length, auth_length

