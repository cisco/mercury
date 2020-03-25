"""
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import os
import sys
import json
import functools
from collections import OrderedDict

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from pmercury.protocols.protocol import Protocol
from pmercury.utils.pmercury_utils import *

MAX_CACHED_RESULTS = 2**24

class TCP():
    def __init__(self, fp_database=None, config=None):
        # populate fingerprint databases
        self.fp_db = None
        self.load_database(fp_database)


    def load_database(self, fp_database):
        fp_database = find_resource_path(fp_database)
        if fp_database == None:
            return

        self.fp_db = {}

        if os.name == 'nt':
            import gzip
            for line in gzip.open(fp_database, 'r'):
                fp_ = json.loads(line)
                fp_['os_info'] = self.clean_os_entry(fp_['os_info'])
                self.fp_db[fp_['str_repr']] = fp_
        else:
            for line in os.popen('zcat %s' % (fp_database)):
                fp_ = json.loads(line)
                fp_['os_info'] = self.clean_os_entry(fp_['os_info'])
                self.fp_db[fp_['str_repr']] = fp_


    def clean_os_entry(self, os_info):
        tmp_os = []
        for k in os_info:
            tmp_os.append((os_info[k],k))
        tmp_os.sort(reverse=True)
        os_info = OrderedDict({})
        for c,k in tmp_os:
            os_info[k] = c
        return os_info


    @functools.lru_cache(maxsize=MAX_CACHED_RESULTS)
    def os_identify(self, fp_str_, list_oses=0):
        fp_ = self.get_database_entry(fp_str_, None)
        if fp_ == None:
            return {'os': 'Unknown', 'score': 0.0}

        r_ = []
        os_info = fp_['os_info']
        fp_tc   = fp_['total_count']
        for k in os_info:
            r_.append({'os': k, 'score': os_info[k]})

        out_ = {'os':r_[0]['os'], 'score':r_[0]['score']}
        if list_oses > 0:
            out_['probable_oses'] = r_[0:list_oses]

        return out_


    @functools.lru_cache(maxsize=MAX_CACHED_RESULTS)
    def get_database_entry(self, fp_str, approx_fp_str):
        if self.fp_db == None or fp_str not in self.fp_db:
            return None

        return self.fp_db[fp_str]


    @staticmethod
    def proto_identify(data, offset, data_len):
        if data[offset+13] != 2:
            return False
        return True


    @staticmethod
    def fingerprint(data, offset, app_offset, data_len):
        c = [f'({data[offset+14]:02x}{data[offset+15]:02x})']

        offset += 20
        while offset < app_offset and offset + 1 < data_len:
            kind   = data[offset]
            length = data[offset+1]
            if kind == 0 or kind == 1: # End of Options / NOP
                c.append('(%02x)' % kind)
                offset += 1
            elif kind != 2 and kind != 3:
                c.append('(%02x)' % kind)
                offset += length
            else:
                c.append('(%02x%s)' % (kind, data[offset+1:offset+length].hex()))
                offset += length

        return ''.join(c), None


    def get_human_readable(self, fp_str_):
        return None


    def proc_identify(self, fp_str_, context_, dst_ip, dst_port, list_procs=0, endpoint=None, approx=True, debug=None):
        return None

