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

MAX_CACHED_RESULTS = 2**24


class TLS_Server(Protocol):

    def __init__(self, fp_database=None, config=None):
        # populate fingerprint databases
        self.fp_db = {}


    @staticmethod
    def proto_identify(data, offset, data_len):
        if data_len-offset < 16:
            return False
        if (data[offset]    == 22 and
            data[offset+1]  ==  3 and
            data[offset+2]  <=  3 and
            data[offset+5]  ==  2 and
            data[offset+9]  ==  3 and
            data[offset+10] <=  3):
            return True
        return False


    @staticmethod
    def fingerprint(bytes data, unsigned int offset, unsigned int data_len):
        cdef unsigned char *buf = data
        offset += 5

        # extract handshake version
        cdef str fp_ = '(%s)' % buf[offset+4:offset+6].hex()

        # skip header/server_random
        offset += 38

        # parse/skip session_id
        cdef unsigned int session_id_length = buf[offset]
        offset += 1 + session_id_length
        if offset >= data_len:
            return None, None

        # parse selected_cipher_suite
        fp_ += '(%s)' % buf[offset:offset+2].hex()
        offset += 2
        if offset >= data_len:
            return fp_+'()', None

        # parse/skip compression method
        cdef unsigned int compression_methods_length = buf[offset]
        offset += 1 + compression_methods_length
        if offset >= data_len:
            return fp_+'()', None

        # parse/skip extensions length
        cdef unsigned int ext_total_len = int.from_bytes(buf[offset:offset+2], 'big')
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


    def get_human_readable(self, fp_str_):
        lit_fp = eval_fp_str(fp_str_)

        fp_h = {}
        fp_h['version'] = get_version_from_str(lit_fp[0][0])
        fp_h['selected_cipher_suite'] = get_cs_from_str(lit_fp[1][0])[0]
        fp_h['extensions'] = []
        if len(lit_fp) > 2:
            fp_h['extensions'] = get_ext_from_str(lit_fp[2], mode='server')

        return fp_h
