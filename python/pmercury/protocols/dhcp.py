"""
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import os
import sys
import functools
from socket import AF_INET, AF_INET6, inet_ntop

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from pmercury.protocols.protocol import Protocol

MAX_CACHED_RESULTS = 2**24

class DHCP(Protocol):

    def __init__(self, fp_database=None, config=None):
        # populate fingerprint databases
        self.fp_db = None

        DHCP.static_data = set([0x35, 0x37])
        DHCP.contextual_data = {0x03: ('router',lambda x: inet_ntop(AF_INET, x)),
                                0x06: ('domain_name_server',lambda x: inet_ntop(AF_INET, x)),
                                0x0c: ('hostname',lambda x: x.decode()),
                                0x0f: ('domain_name',lambda x: x.decode()),
                                0x32: ('requested_ip',lambda x: inet_ntop(AF_INET, x)),
                                0x3c: ('vendor_class_id',lambda x: x.decode())}

    @staticmethod
    def proto_identify(data, offset, data_len):
        if data_len < 230:
            return False
        if (data[offset]     != 0x01 or
            data[offset+236] != 0x63 or
            data[offset+237] != 0x82 or
            data[offset+238] != 0x53 or
            data[offset+239] != 0x63):
            return False
        return True


    @staticmethod
    def fingerprint(data, offset, data_len):
        hardware_address_length = data[offset + 2]

        cmac = data[offset+28:offset+28+hardware_address_length].hex()
        context = [{'name': 'client_mac_address', 'data': '%s' % ':'.join(a+b for a,b in zip(cmac[::2], cmac[1::2]))}]
        offset += 240
        fp_ = '('
        while offset < data_len:
            kind = data[offset]
            if kind == 0xff or kind == 0x00: # End / Padding
                fp_ += '(%02x)' % kind
                break

            length = data[offset+1]
            if kind in DHCP.contextual_data:
                name_, transform_ = DHCP.contextual_data[kind]
                context.append({'name':name_,
                                'data':transform_(data[offset+2:offset+2+length])})
            if offset+length+2 >= data_len:
                return None
            if kind not in DHCP.static_data:
                fp_ += '(%02x)' % kind
                offset += length+2
                continue

            fp_ += '(%s)' % data[offset:offset+2+length].hex()
            offset += length+2
        fp_ += ')'

        return fp_, context

