#!/usr/bin/env python3

"""     
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import os
import sys
from sys import path
from binascii import hexlify

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from utils.tls_utils import *
from utils.tls_constants import *
from protocol import Protocol

MAX_CACHED_RESULTS = 2**24


class TLS_Server(Protocol):

    def __init__(self, fp_database=None, config=None):
        # populate fingerprint databases
        self.fp_db = {}


    def fingerprint(self, data, offset, data_len):
        if (data[offset]    != 22 or
            data[offset+1]  !=  3 or
            data[offset+2]  >   3 or
            data[offset+5]  !=  2 or
            data[offset+9]  !=  3 or
            data[offset+10] >   3):
            return None, None, None, []

        # extract fingerprint string
        fp_str_ = self.extract_fingerprint(data, offset+5, data_len)
        if fp_str_ == None:
            return None, None, None, None

        return 'tls_server', fp_str_, None, None


    def extract_fingerprint(self, data, offset, data_len):
        # extract handshake version
        fp_ = b'(' + hexlify(data[offset+4:offset+6]) + b')'

        # skip header/server_random
        offset += 38

        # parse/skip session_id
        session_id_length = int.from_bytes(data[offset:offset+1], 'big')
        offset += 1 + session_id_length
        if offset >= data_len:
            return None

        # parse selected_cipher_suite
        fp_ += b'(' + hexlify(data[offset:offset+2]) + b')'
        offset += 2
        if offset >= data_len:
            return None

        # parse/skip compression method
        compression_methods_length = int.from_bytes(data[offset:offset+1], 'big')
        offset += 1 + compression_methods_length
        if offset >= data_len:
            return fp_

        # parse/skip extensions length
        ext_total_len = int.from_bytes(data[offset:offset+2], 'big')
        offset += 2
        if offset >= data_len:
            return None

        # parse/extract/skip extension type/length/values
        fp_ += b'('
        while ext_total_len > 0:
            if offset >= data_len:
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

        fp_h = {}
        fp_h['version'] = get_version_from_str(lit_fp[0][0])
        fp_h['selected_cipher_suite'] = get_cs_from_str(lit_fp[1][0])[0]
        fp_h['extensions'] = []
        if len(lit_fp) > 2:
            fp_h['extensions'] = get_ext_from_str(lit_fp[2], mode='server')

        return fp_h
