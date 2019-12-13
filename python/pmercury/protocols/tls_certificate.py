"""
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import os
import sys
import base64

# TLS helper classes
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from pmercury.protocols.protocol import Protocol
from pmercury.utils.tls_utils import *
from pmercury.utils.tls_constants import *


class TLS_Certificate(Protocol):
    def __init__(self):
        self.fp_db = None


    @staticmethod
    def proto_identify(data, offset):
        if (data[offset]   == 22 and
            data[offset+1] ==  3 and
            data[offset+2] <=  3 and
            data[offset+5] == 11):
            return True
        return False


    @staticmethod
    def proto_identify_hs(data, offset):
        if (data[offset]   == 11 and
            data[offset+1] ==  0 and
            data[offset+4] ==  0 and
            data[offset+7] ==  0):
            return True
        return False


    @staticmethod
    def proto_identify_sh(data, offset):
        if (data[offset]    == 22 and
            data[offset+1]  ==  3 and
            data[offset+2]  <=  3 and
            data[offset+5]  ==  2 and
            data[offset+9]  ==  3 and
            data[offset+10] <=  3):
            return True
        return False


    @staticmethod
    def fingerprint(data, app_offset, data_len):
        data_len = len(data)
        offset = app_offset

        if (data[offset]    == 22 and
            data[offset+1]  ==  3 and
            data[offset+2]  <=  3 and
            data[offset+5]  ==  2 and
            data[offset+9]  ==  3 and
            data[offset+10] <=  3):
            offset += 9+int(data[offset+6:offset+9].hex(),16)
            if offset >= data_len:
                return None, None

        if (data[offset]   == 22 and
            data[offset+1] ==  3 and
            data[offset+2] <=  3 and
            data[offset+5] == 11 and
            data[offset+6] ==  0):
            offset += 5
        elif (data[offset]   == 11 and
              data[offset+1] ==  0 and
              data[offset+4] ==  0 and
              data[offset+7] ==  0):
            pass
        else:
            return None, None

        certificates_length = int(data[offset+4:offset+7].hex(),16)
        offset += 7
        if offset >= data_len:
            return None, None

        certs = []
        while offset < certificates_length:
            cert_len = int(data[offset:offset+3].hex(),16)
            offset += 3
            if offset >= data_len:
                return certs, None

            certs.append(base64.b64encode(data[offset:offset+cert_len]).decode())

            offset += cert_len
            if offset >= data_len:
                return certs, None

        return certs, None


    @staticmethod
    def fingerprint_old(data, app_offset, data_len):
        data = data[app_offset:]

        sh = False
        if TLS_Certificate.proto_identify_sh(data,0):
            data = data[9+int(data[6:9].hex(),16):]
            if len(data) == 0:
                return None, None
            sh = True

        if TLS_Certificate.proto_identify(data,0):
            offset = 5
        elif TLS_Certificate.proto_identify_hs(data,0):
            offset = 0
        else:
            return None, None

        certificates_length = int(data[offset+4:offset+7].hex(),16)
        data_len = len(data)
        offset += 7
        if offset >= data_len:
            return None, None

        certs = []
        while offset < certificates_length:
            cert_len = int(data[offset:offset+3].hex(),16)
            offset += 3
            if offset >= data_len:
                return certs, None

            certs.append(base64.b64encode(data[offset:cert_len]).decode())

            offset += cert_len
            if offset >= data_len:
                return certs, None

        return certs, None


    def get_human_readable(self, fp_str_):
        return None


    def proc_identify(self, fp_str_, context_, dst_ip, dst_port, list_procs=5):
        return None

