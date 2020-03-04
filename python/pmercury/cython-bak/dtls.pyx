#cython: language_level=3, wraparound=False, cdivision=True, infer_types=True, initializedcheck=False, c_string_type=bytes, embedsignature=False, nonecheck=False

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

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from pmercury.utils.tls_utils import *

from cython.operator cimport dereference as deref
from libc.math cimport exp, log, fmax
from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t

IF UNAME_SYSNAME == "Windows":
    cdef extern from "winsock2.h":
        uint16_t htons(uint16_t hostshort)
ELSE:
    cdef extern from "arpa/inet.h":
        uint16_t htons(uint16_t hostshort)

MAX_CACHED_RESULTS = 2**24


cdef class DTLS():
    cdef dict fp_db

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
    def fingerprint(bytes data, unsigned int offset, unsigned int data_len):
        cdef unsigned char *buf = data
        offset += 13

        # extract handshake version
        cdef list c = [f'({buf[offset+12]:02x}{buf[offset+13]:02x})']

        # skip header/client_random
        offset += 46

        # parse/skip session_id
        cdef uint8_t session_id_length = buf[offset]
        offset += 1 + session_id_length
        if offset >= data_len:
            return None, None

        # parse/skip cookie
        cdef uint8_t cookie_length = buf[offset]
        offset += 1 + cookie_length
        if offset >= data_len:
            return None, None

        # parse/extract/skip cipher_suites length
        cdef uint16_t cipher_suites_length = htons(deref(<uint16_t *>(buf+offset)))
        offset += 2
        if offset >= data_len:
            return None, None

        # parse/extract/skip cipher_suites
        cdef str cs_ = degrease_type_code(data, offset)
        if cipher_suites_length > 2:
            cs_ += buf[offset+2:offset+cipher_suites_length].hex()
        c.append('(%s)' % cs_)
        offset += cipher_suites_length
        if offset >= data_len:
            c.append('()')
            return ''.join(c), None

        # parse/skip compression method
        cdef uint8_t compression_methods_length = buf[offset]
        offset += 1 + compression_methods_length
        if offset >= data_len:
            c.append('()')
            return ''.join(c), None

        # parse/skip extensions length
        cdef uint16_t ext_total_len = htons(deref(<uint16_t *>(buf+offset)))
        offset += 2
        if offset >= data_len:
            c.append('()')
            return ''.join(c), None

        # parse/extract/skip extension type/length/values
        c.append('(')
        server_name = None
        while ext_total_len > 0:
            if offset >= data_len:
                c.append(')')
                return ''.join(c), server_name

            # extract server name for process/malware identification
            if htons(deref(<uint16_t *>(buf+offset))) == 0:
                server_name = extract_server_name(data, offset+2, data_len)

            tmp_fp_ext, offset, ext_len = parse_extension(data, offset)
            if ext_len+4 > ext_total_len:
                c.append(')')
                return ''.join(c), server_name
            c.append('(%s)' % tmp_fp_ext)

            ext_total_len -= 4 + ext_len
        c.append(')')

        cdef list context = None
        if server_name != None:
            context = [{'name':'server_name', 'data':server_name}]

        return  ''.join(c), context


    @functools.lru_cache(maxsize=MAX_CACHED_RESULTS)
    def get_database_entry(self, fp_str, approx_fp_str):
        return None


    def get_human_readable(self, fp_str_):
        return None


    def proc_identify(self, fp_str_, context_, dst_ip, dst_port, list_procs=5):
        return None

