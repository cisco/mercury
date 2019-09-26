#!/usr/bin/env python3

"""     
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import os
import re
import sys
import gzip
import copy
import time
import struct
import operator
import functools
import ujson as json
from sys import path
from math import exp, log
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
        self.pattern = b'\x16\x03[\x00-\x03].{2}\x02.{3}\x03[\x00-\x03]'


    def fingerprint(self, data):
        # check TLS version and record/handshake type
        if re.findall(self.pattern, data[0:11], re.DOTALL) == []:
            return None, None, None, None

        # bounds checking
        message_length = int(hexlify(data[6:9]),16)
        if message_length > len(data[9:]):
            return None, None, None, None

        # extract fingerprint string
        fp_str_ = self.extract_fingerprint(data[5:])
        fp_str_ = str(fp_str_)
        fp_str_ = bytes(fp_str_.replace('()',''),'utf-8')

        return 'tls_server', fp_str_, None, None


    def extract_fingerprint(self, data):
        # extract handshake version
        fp_ = data[4:6]

        # skip header/server_random
        offset = 38

        # parse/skip session_id
        session_id_length = int(hexlify(data[offset:offset+1]),16)
        offset += 1 + session_id_length
        if len(data[offset:]) == 0:
            return None, None

        # parse selected_cipher_suite
        fp_ += data[offset:offset+2]
        offset += 2
        if len(data[offset:]) == 0:
            return None, None

        # parse/skip compression method
        compression_methods_length = int(hexlify(data[offset:offset+1]),16)
        offset += 1 + compression_methods_length
        if len(data[offset:]) == 0:
            return hex_fp_to_structured_representation(hexlify(fp_)), None

        # parse/skip extensions length
        ext_total_len = int(hexlify(data[offset:offset+2]),16)
        offset += 2
        if len(data[offset:]) < ext_total_len:
            return None, None

        # parse/extract/skip extension type/length/values
        fp_ext_ = b''
        ext_fp_len_ = 0
        while ext_total_len > 0:
            if len(data[offset:]) == 0:
                return None, None

            tmp_fp_ext, offset, ext_len = parse_extension(data, offset)
            fp_ext_ += tmp_fp_ext
            ext_fp_len_ += len(tmp_fp_ext)

            ext_total_len -= 4 + ext_len

        fp_ += unhexlify(('%04x' % ext_fp_len_))
        fp_ += fp_ext_

        return hex_fp_to_structured_representation_server(hexlify(fp_))


    def get_human_readable(self, fp_str_):
        lit_fp = eval_fp_str(fp_str_)
        fp_h = OrderedDict({})
        fp_h['version'] = get_version_from_str(lit_fp[0][0])
        fp_h['selected_cipher_suite'] = get_cs_from_str(lit_fp[1][0])
        fp_h['extensions'] = []
        if len(lit_fp) > 2:
            fp_h['extensions'] = get_ext_from_str(lit_fp[2])

        return fp_h
