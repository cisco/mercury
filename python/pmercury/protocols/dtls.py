"""
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import os
import sys
import json
import operator
import functools
from sys import path
from socket import htons

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from pmercury.utils.tls_utils import *


MAX_CACHED_RESULTS = 2**24


class DTLS():
    def __init__(self, fp_database=None, config=None):
        self.fp_db = None


    @staticmethod
    def proto_identify(data, offset, data_len):
        if data_len-offset < 27:
            return False
        if (data[offset]    ==  22 and
            data[offset+1]  == 254 and
            data[offset+2]  >= 253 and
            data[offset+13] ==   1 and
            data[offset+25] == 254 and
            data[offset+26] >= 253):
            return True
        return False


    @staticmethod
    def fingerprint(data, offset, data_len):
        offset += 13

        # extract handshake version
        c = [f'({data[offset+12]:02x}{data[offset+13]:02x})']

        # skip header/client_random
        offset += 46

        # parse/skip session_id
        session_id_length = data[offset]
        offset += 1 + session_id_length
        if offset >= data_len:
            return None, None

        # parse/skip cookie
        cookie_length = data[offset]
        offset += 1 + cookie_length
        if offset >= data_len:
            return None, None

        # parse/extract/skip cipher_suites length
        cipher_suites_length = int.from_bytes(data[offset:offset+2], byteorder='big')
        offset += 2
        if offset >= data_len:
            return None, None

        # parse/extract/skip cipher_suites
        cs_ = degrease_type_code(data, offset)
        if cipher_suites_length > 2:
            cs_ += data[offset+2:offset+cipher_suites_length].hex()
        c.append('(%s)' % cs_)
        offset += cipher_suites_length
        if offset >= data_len:
            c.append('()')
            return ''.join(c), None

        # parse/skip compression method
        compression_methods_length = data[offset]
        offset += 1 + compression_methods_length
        if offset >= data_len:
            c.append('()')
            return ''.join(c), None

        # parse/skip extensions length
        ext_total_len = int.from_bytes(data[offset:offset+2], byteorder='big')
        offset += 2
        if offset >= data_len:
            c.append('()')
            return ''.join(c), None

        # parse/extract/skip extension type/length/values
        c.append('(')
        server_name = None
        context = None
        while ext_total_len > 0:
            if offset >= data_len:
                c.append(')')
                return ''.join(c), server_name

            # extract server name for process/malware identification
            if int.from_bytes(data[offset:offset+2], byteorder='big') == 0:
                server_name = extract_server_name(data, offset+2, data_len)
                context = [{'name':'server_name', 'data':server_name}]

            tmp_fp_ext, offset, ext_len = parse_extension(data, offset)
            if ext_len+4 > ext_total_len:
                c.append(')')
                return ''.join(c), server_name
            c.append('(%s)' % tmp_fp_ext)

            ext_total_len -= 4 + ext_len
        c.append(')')

        return  ''.join(c), context


    @functools.lru_cache(maxsize=MAX_CACHED_RESULTS)
    def get_database_entry(self, fp_str, approx_fp_str):
        return None


    def get_human_readable(self, fp_str_):
        return None


    def proc_identify(self, fp_str_, context_, dst_ip, dst_port, list_procs=5):
        return None

