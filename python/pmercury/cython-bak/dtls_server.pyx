#cython: language_level=3, wraparound=False, cdivision=True, infer_types=True, initializedcheck=False, c_string_type=bytes, embedsignature=False

"""
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from pmercury.utils.tls_utils import *
from pmercury.utils.tls_constants import *
from pmercury.protocols.protocol import Protocol

import functools

from cython.operator cimport dereference as deref
from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t

IF UNAME_SYSNAME == "Windows":
    cdef extern from "winsock2.h":
        uint16_t htons(uint16_t hostshort)
ELSE:
    cdef extern from "arpa/inet.h":
        uint16_t htons(uint16_t hostshort)


MAX_CACHED_RESULTS = 2**24


class DTLS_Server(Protocol):

    def __init__(self, fp_database=None, config=None):
        # populate fingerprint databases
        self.fp_db = {}


    @staticmethod
    def proto_identify(data, offset, data_len):
        if data_len-offset < 27:
            return False
        if (data[offset]    ==  22 and
            data[offset+1]  == 254 and
            data[offset+2]  >= 253 and
            data[offset+13] ==   2 and
            data[offset+25] == 254 and
            data[offset+26] >= 253):
            return True
        return False


    @staticmethod
    def fingerprint(bytes data, unsigned int offset, unsigned int data_len):
        cdef unsigned char *buf = data
        offset += 13

        # extract handshake version
        cdef str fp_ = f'({buf[offset+12]:02x}{buf[offset+13]:02x})'

        # skip header/server_random
        offset += 46

        # parse/skip session_id
        cdef unsigned int session_id_length = buf[offset]
        offset += 1 + session_id_length
        if offset >= data_len:
            return None, None

        # parse selected_cipher_suite
        fp_ += f'({buf[offset]:02x}{buf[offset+1]:02x})'
        offset += 2
        if offset >= data_len:
            return fp_+'()', None

        # parse/skip compression method
        cdef unsigned int compression_methods_length = buf[offset]
        offset += 1 + compression_methods_length
        if offset >= data_len:
            return fp_+'()', None

        # parse/skip extensions length
        cdef unsigned int ext_total_len = htons(deref(<uint16_t *>(buf+offset)))
        offset += 2
        if offset >= data_len:
            return fp_+'()', None

        # parse/extract/skip extension type/length/values
        cdef str tmp_fp_ext
        cdef unsigned int ext_len
        fp_ += '('
        while ext_total_len > 0:
            if offset >= data_len:
                return fp_+')', None

            tmp_fp_ext, offset, ext_len = parse_extension(data, offset)
            fp_ += '(%s)' % tmp_fp_ext

            ext_total_len -= 4 + ext_len
        fp_ += ')'

        return fp_, None


    @functools.lru_cache(maxsize=MAX_CACHED_RESULTS)
    def get_database_entry(self, fp_str, approx_fp_str):
        return None


    def get_human_readable(self, fp_str_):
        return None


    def proc_identify(self, fp_str_, context_, dst_ip, dst_port, list_procs=5):
        return None

