#!/usr/bin/env python3

"""     
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import os
import sys
from sys import path
from binascii import hexlify, unhexlify

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from utils.tls_utils import *
from utils.tls_constants import *
from protocol import Protocol

MAX_CACHED_RESULTS = 2**24


class TLS_Server(Protocol):

    def __init__(self, fp_database=None):
        # populate fingerprint databases
        self.fp_db = {}

        # TLS ServerHello pattern/RE
        self.tls_server_hello_mask  = b'\xff\xff\xfc\x00\x00\xff\x00\x00\x00\xff\xfc'
        self.tls_server_hello_value = b'\x16\x03\x00\x00\x00\x02\x00\x00\x00\x03\x00'


    def fingerprint(self, data):
        if len(data) < 32:
            return None, None, None, []
        # check TLS version and record/handshake type
        for i in range(11):
            if (data[i] & self.tls_server_hello_mask[i]) != self.tls_server_hello_value[i]:
                return None, None, None, []

        # bounds checking
        message_length = int.from_bytes(data[6:9], 'big')
        if message_length > len(data[9:]):
            return None, None, None, None

        # extract fingerprint string
        fp_str_ = self.extract_fingerprint(data[5:])
        if fp_str_ == None:
            return None, None, None, None

        return 'tls_server', fp_str_, None, None


    def extract_fingerprint(self, data):
        data_len = len(data)

        # extract handshake version
        fp_ = b'(' + hexlify(data[4:6]) + b')'

        # skip header/server_random
        offset = 38

        # parse/skip session_id
        session_id_length = int.from_bytes(data[offset:offset+1], 'big')
        offset += 1 + session_id_length
        if data_len - offset <= 0:
            return None

        # parse selected_cipher_suite
        fp_ += b'(' + hexlify(data[offset:offset+2]) + b')'
        offset += 2
        if data_len - offset <= 0:
            return None

        # parse/skip compression method
        compression_methods_length = int.from_bytes(data[offset:offset+1], 'big')
        offset += 1 + compression_methods_length
        if data_len - offset <= 0:
            return fp_

        # parse/skip extensions length
        ext_total_len = int.from_bytes(data[offset:offset+2], 'big')
        offset += 2
        if data_len - offset <= 0:
            return None

        # parse/extract/skip extension type/length/values
        fp_ += b'('
        while ext_total_len > 0:
            if data_len - offset <= 0:
                return None

            fp_ += b'('
            tmp_fp_ext, offset, ext_len = parse_extension(data, offset)
            fp_ += tmp_fp_ext

            ext_total_len -= 4 + ext_len
            fp_ += b')'
        fp_ += b')'

        return fp_


    def get_human_readable(self, fp_str_):
        lit_fp = eval_fp_str(fp_str_)

        fp_h = OrderedDict({})
        fp_h['version'] = get_version_from_str(lit_fp[0][0])
        fp_h['selected_cipher_suite'] = get_cs_from_str(lit_fp[1][0])[0]
        fp_h['extensions'] = []
        if len(lit_fp) > 2:
            fp_h['extensions'] = get_ext_from_str(lit_fp[2], mode='server')

        return fp_h
