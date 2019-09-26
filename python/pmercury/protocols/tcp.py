"""     
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import os
import sys
import functools
import ujson as json
from binascii import hexlify, unhexlify

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from protocol import Protocol

MAX_CACHED_RESULTS = 2**24

class TCP(Protocol):

    def __init__(self, fp_database=None):
        # populate fingerprint databases
        self.fp_db = None
        self.load_database(fp_database)

        self.tcp_options_data = set([0,1,2,3])

    def load_database(self, fp_database):
        if fp_database == None:
            return

        self.fp_db = {}
        for line in os.popen('zcat %s' % (fp_database)):
            fp_ = json.loads(line)
            fp_['str_repr'] = bytes(fp_['str_repr'],'utf-8')

            self.fp_db[fp_['str_repr']] = fp_


    @functools.lru_cache(maxsize=MAX_CACHED_RESULTS)
    def os_identify(self, fp_str_, list_oses=0):
        fp_ = self.get_database_entry(fp_str_)
        if fp_ == None:
            return {'os': 'Unknown', 'score': 0.0}

        r_ = []
        os_info = fp_['os_info']
        fp_tc   = fp_['total_count']
        for k in os_info.keys():
            r_.append({'os': k, 'score': os_info[k]})

        out_ = {'os':r_[0]['os'], 'score':r_[0]['score']}
        if list_oses > 0:
            out_['probable_oses'] = r_[0:list_oses]

        return out_


    @functools.lru_cache(maxsize=MAX_CACHED_RESULTS)
    def get_database_entry(self, fp_str):
        if self.fp_db == None or fp_str not in self.fp_db:
            return None

        return self.fp_db[fp_str]


    def fingerprint(self, data):
        if data.flags == 2:
            options = data.opts
            fp_str_ = self.extract_fingerprint(options)
            return 'tcp', fp_str_, None, None

        return None, None, None, None


    def extract_fingerprint(self, options):
        idx = 0

        fp_str = ''
        while idx < len(options):
            opt = b''
            kind = options[idx]
            opt += b'%02x' % options[idx]
            if options[idx] == 1: # NOP
                fp_str += '(' + str(opt,'utf-8') + ')'
                idx += 1
                continue

            length = options[idx+1]
            if options[idx] not in self.tcp_options_data:
                idx += length
                fp_str += '(' + str(opt,'utf-8') + ')'
                continue

            data = ''
            if length-2 > 0:
                opt += b'%02x' % options[idx+1]
                for i in range(idx+2, idx+2+length-2):
                    opt += b'%02x' % options[i]
            idx += length

            fp_str += '(' + str(opt,'utf-8') + ')'

        return fp_str
