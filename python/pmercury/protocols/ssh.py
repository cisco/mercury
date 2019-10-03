import os
import re
import sys
import dpkt
import socket
from collections import OrderedDict
from binascii import hexlify, unhexlify

# SSH helper classes
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from protocol import Protocol


class SSH(Protocol):
    def __init__(self, fp_database=None):
        # SSH initial packet pattern
        self.pattern = b'\x53\x53\x48\x2d'

        self.session_data = {}


    def get_flow_key(self, ip):
        tcp_data = ip.data

        if type(ip) == dpkt.ip.IP:
            add_fam = socket.AF_INET
        else:
            add_fam = socket.AF_INET6
        src_ip   = socket.inet_ntop(add_fam,ip.src)
        dst_ip   = socket.inet_ntop(add_fam,ip.dst)
        src_port = str(tcp_data.sport)
        dst_port = str(tcp_data.dport)
        pr       = '6' # currently only support TCP

        return src_ip + ':' + dst_ip + ':' + src_port + ':' + dst_port + ':' + pr


    def fingerprint(self, ip):
        protocol_type = 'ssh'
        fp_str_ = None
        data = ip.data.data
        if len(data) == 0:
            return protocol_type, fp_str_, None, None

        flow_key = self.get_flow_key(ip)

        if flow_key not in self.session_data and re.findall(self.pattern, data[0:4]) == []:
            return protocol_type, fp_str_, None, None
        elif re.findall(self.pattern, data[0:4]) != []:
            self.session_data[flow_key] = {}
            self.session_data[flow_key]['protocol'] = data
            self.session_data[flow_key]['kex'] = b''
            return protocol_type, fp_str_, None, None

        data = self.session_data[flow_key]['kex'] + data
        if len(data) >= 4096:
            del self.session_data[flow_key]
            return protocol_type, fp_str_, None, None

        # check SSH packet length to limit possibility of parsing junk and handle fragmentation
        if int(hexlify(data[0:4]),16) + 4 > len(data):
            self.session_data[flow_key]['kex'] += data
            return protocol_type, fp_str_, None, None

        # check to make sure message code is key exchange init
        if data[5] != 20:
            del self.session_data[flow_key]
            return protocol_type, fp_str_, None, None

        # extract fingerprint string
        self.session_data[flow_key]['kex'] = data
        fp_str_ = self.extract_fingerprint(self.session_data[flow_key])
        del self.session_data[flow_key]

        return protocol_type, fp_str_, None, None


    def extract_fingerprint(self, ssh_):
        fp_str_ = b''

        fp_str_ += b'(' + hexlify(ssh_['protocol'][:-2]) + b')'

        data = ssh_['kex']
        kex_length = int(hexlify(data[0:4]),16)

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
        len_ = int(hexlify(data[offset:offset+4]),16)
        fp_str_ += b'(' + hexlify(data[offset+4:offset+4+len_]) + b')'
        offset += 4 + len_
        if offset > len(data):
            return None, None
        return fp_str_, offset


    def get_human_readable(self, fp_str_):
        fields = [unhexlify(s_[1:]) for s_ in fp_str_.split(b')')[:-1]]

        fp_h = OrderedDict({})
        fp_h['protocol']         = fields[0].split(b',')
        fp_h['kex_algos']        = fields[1].split(b',')
        fp_h['s_host_key_algos'] = fields[2].split(b',')
        fp_h['c_enc_algos']      = fields[3].split(b',')
        fp_h['s_enc_algos']      = fields[4].split(b',')
        fp_h['c_mac_algos']      = fields[5].split(b',')
        fp_h['s_mac_algos']      = fields[6].split(b',')
        fp_h['c_comp_algos']     = fields[7].split(b',')
        fp_h['s_comp_algos']     = fields[8].split(b',')
        fp_h['c_languages']      = fields[9].split(b',')
        fp_h['s_languages']      = fields[10].split(b',')

        return fp_h

