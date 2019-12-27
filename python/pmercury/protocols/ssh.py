"""
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import os
import sys
import socket

# SSH helper classes
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from pmercury.protocols.protocol import Protocol


class SSH(Protocol):
    def __init__(self, fp_database=None, config=None):
        self.session_data = {}


    def get_flow_key(self, data, ip_offset, tcp_offset, ip_type, ip_length):
        src_port = data[tcp_offset:tcp_offset+2]
        dst_port = data[tcp_offset+2:tcp_offset+4]
        if ip_type == 'ipv4':
            o_ = ip_offset+ip_length-8
            src_addr = data[o_:o_+4]
            o_ = ip_offset+ip_length-4
            dst_addr = data[o_:o_+4]
        else:
            o_ = ip_offset+ip_length-32
            src_addr = data[o_:o_+16]
            o_ = ip_offset+ip_length-16
            dst_addr = data[o_:o_+16]
        pr = b'\x06' # currently only support TCP

        return b''.join([src_addr,dst_addr,src_port,dst_port,pr])


    def proto_identify(self, data, offset):
        if (data[offset]   == 83 and
            data[offset+1] == 83 and
            data[offset+2] == 72 and
            data[offset+3] == 45):
            return True
        return False


    def fingerprint(self, data, ip_offset, tcp_offset, app_offset, ip_type, ip_length, data_len):
        protocol_type = 'ssh'
        fp_str_ = None
        if app_offset+4 >= data_len:
            return protocol_type, fp_str_, None

        flow_key = self.get_flow_key(data, ip_offset, tcp_offset, ip_type, ip_length)

        data = data[app_offset:]

        if flow_key not in self.session_data and self.proto_identify(data,0) == False:
            return protocol_type, fp_str_, None
        elif self.proto_identify(data,0):
            self.session_data[flow_key] = {}
            self.session_data[flow_key]['protocol'] = data
            self.session_data[flow_key]['kex'] = b''
            return protocol_type, fp_str_, None

        data = self.session_data[flow_key]['kex'] + data
        if len(data) >= 4096:
            del self.session_data[flow_key]
            return protocol_type, fp_str_, None

        # check SSH packet length to limit possibility of parsing junk and handle fragmentation
        if int.from_bytes(data[0:4], byteorder='big') + 4 > len(data):
            self.session_data[flow_key]['kex'] += data
            return protocol_type, fp_str_, None

        # check to make sure message code is key exchange init
        if data[5] != 20:
            del self.session_data[flow_key]
            return protocol_type, fp_str_, None

        # extract fingerprint string
        self.session_data[flow_key]['kex'] = data
        fp_str_ = self.extract_fingerprint(self.session_data[flow_key])
        del self.session_data[flow_key]

        return protocol_type, fp_str_, None


    def extract_fingerprint(self, ssh_):
        fp_str_ = ''

        fp_str_ += '(' + ssh_['protocol'][:-2].hex() + ')'

        data = ssh_['kex']
        kex_length = int.from_bytes(data[0:4], byteorder='big')

        # skip over message headers and Cookie field
        offset = 22
        if offset > len(data):
            return None

        # parse kex algorithms
        for i in range(10):
            fp_str_, offset = self.parse_kex_field(data, offset, fp_str_)
            if offset == None:
                return None

        return fp_str_


    def parse_kex_field(self, data, offset, fp_str_):
        len_ = int.from_bytes(data[offset:offset+4], byteorder='big')
        fp_str_ += '(' + data[offset+4:offset+4+len_].hex() + ')'
        offset += 4 + len_
        if offset > len(data):
            return None, None
        return fp_str_, offset


    def get_human_readable(self, fp_str_):
        fields = [bytes.fromhex(s_[1:]) for s_ in fp_str_.split(')')[:-1]]

        fp_h = {}
        fp_h['protocol']         = fields[0].decode().split(',')
        fp_h['kex_algos']        = fields[1].decode().split(',')
        fp_h['s_host_key_algos'] = fields[2].decode().split(',')
        fp_h['c_enc_algos']      = fields[3].decode().split(',')
        fp_h['s_enc_algos']      = fields[4].decode().split(',')
        fp_h['c_mac_algos']      = fields[5].decode().split(',')
        fp_h['s_mac_algos']      = fields[6].decode().split(',')
        fp_h['c_comp_algos']     = fields[7].decode().split(',')
        fp_h['s_comp_algos']     = fields[8].decode().split(',')
        fp_h['c_languages']      = fields[9].decode().split(',')
        fp_h['s_languages']      = fields[10].decode().split(',')

        return fp_h

