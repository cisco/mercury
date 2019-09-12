"""     
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import dpkt
from binascii import hexlify, unhexlify

from protocol import Protocol


class TCP(Protocol):

    def __init__(self, fp_database=None):
        # populate fingerprint databases
        self.fp_db = {}
        self.tcp_options_data = set([0,1,2,3])

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
