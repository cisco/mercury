"""     
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import os
import sys
import functools
import ujson as json

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from pmercury.protocols.protocol import Protocol

MAX_CACHED_RESULTS = 2**24

class TCP(Protocol):

    def __init__(self, fp_database=None, config=None):
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
            fp_['str_repr'] = fp_['str_repr'].encode()

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


    @staticmethod
    def proto_identify(data, offset, data_len):
        if data[offset+13] != 2:
            return False
        return True


    @staticmethod
    def fingerprint(data, offset, data_len):
        fp_ = '(%s)' % data[offset+14:offset+16].hex()

        offset += 20
        cur_ = 20
        while cur_ < data_len:
            kind   = data[offset]
            if kind == 0 or kind == 1: # End of Options / NOP
                fp_ += '(%02x)' % kind
                offset += 1
                cur_ += 1
                continue

            length = data[offset+1]
            if cur_ >= data_len:
                return None
            if kind != 2 and kind != 3:
                fp_ += '(%02x)' % kind
                offset += length
                cur_ += length
                continue

            fp_ += '(%02x%s)' % (kind, data[offset+1:offset+length].hex())
            offset += length
            cur_ += length

        return fp_, None

