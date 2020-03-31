"""
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import sys

from pmercury.protocols.tcp import TCP
from pmercury.protocols.tls import TLS
from pmercury.protocols.dtls import DTLS
from pmercury.protocols.http import HTTP
from pmercury.protocols.dhcp import DHCP
from pmercury.protocols.iquic import IQUIC
from pmercury.protocols.tls_server import TLS_Server
from pmercury.protocols.dtls_server import DTLS_Server
from pmercury.protocols.http_server import HTTP_Server
from pmercury.protocols.tls_certificate import TLS_Certificate


def pkt_proc(ts, data):
    buf = data

    ip_type = 4

    if buf[12] == 0x08 and buf[13] == 0x00: # IPv4
        ip_length = 20
        ip_offset = 14
        protocol  = buf[23]
    elif buf[12] == 0x86 and buf[13] == 0xdd: # IPv6
        ip_type   = 6
        ip_length = 40
        ip_offset = 14
        protocol  = buf[20]
    elif buf[14] == 0x08 and buf[15] == 0x00: # IPv4 (hack for linux cooked capture)
        ip_length = 20
        ip_offset = 16
        protocol  = buf[25]
    elif buf[12] == 0x81 and buf[13] == 0x00: # IPv4 (hack for 802.1Q Virtual LAN)
        if buf[16] == 0x08 and buf[17] == 0x00: # IPv4
            ip_length = 20
            ip_offset = 18
            protocol  = buf[27]
        elif buf[16] == 0x86 and buf[17] == 0xdd: # IPv6
            ip_type   = 6
            ip_length = 40
            ip_offset = 18
            protocol  = buf[24]
        else:
            return None
    else: # currently skip other types
        return None

    data_len  = len(data)
    fp_str_   = None
    fp_str_2_ = None
    prot_offset = 0
    if protocol == 6:
        prot_offset = ip_offset+ip_length
        if prot_offset+20 > data_len:
            return None
        prot_length = (buf[prot_offset+12] >> 0x04)*4
        app_offset = prot_offset + prot_length
        if buf[prot_offset+13] & 0x12 == 2:
            fp_str_, context_ = TCP.fingerprint(data, prot_offset, app_offset, data_len)
            fp_type = 'tcp'
        elif data_len - app_offset < 16:
            return None
        elif buf[app_offset] == 22 and buf[app_offset+1] == 3:
            if buf[app_offset+5]  ==  1 and buf[app_offset+9] == 3:
                fp_str_, context_ = TLS.fingerprint(data, app_offset, data_len)
                fp_type = 'tls'
            elif buf[app_offset+5]  ==  2 and buf[app_offset+9] == 3:
                fp_str_, context_     = TLS_Server.fingerprint(data, app_offset, data_len)
                fp_type = 'tls_server'
                fp_str_2_, context_2_ = TLS_Certificate.fingerprint(data, app_offset, data_len)
                fp_type_2 = 'server_certs'
            elif buf[app_offset+5]  ==  11:
                fp_str_, context_ = TLS_Certificate.fingerprint(data, app_offset, data_len)
                fp_type = 'server_certs'
        elif buf[app_offset+2] == 84:
            if (buf[app_offset] == 71 and buf[app_offset+3] == 32):
                fp_str_, context_ = HTTP.fingerprint(data, app_offset, data_len)
                fp_type = 'http'
            elif (buf[app_offset] == 72 and buf[app_offset+5] == 49):
                fp_str_, context_ = HTTP_Server.fingerprint(data, app_offset, data_len)
                fp_type = 'http_server'
    elif protocol == 17:
        prot_offset = ip_offset+ip_length
        prot_length = 8
        app_offset = prot_offset + prot_length

        if data_len - app_offset < 16:
            return None
        elif buf[app_offset] == 22 and buf[app_offset+1] == 254:
            if buf[app_offset+13]  ==  1 and buf[app_offset+25] == 254:
                fp_str_, context_ = DTLS.fingerprint(data, app_offset, data_len)
                fp_type = 'dtls'
            elif buf[app_offset+13]  ==  2 and buf[app_offset+25] == 254:
                fp_str_, context_ = DTLS_Server.fingerprint(data, app_offset, data_len)
                fp_type = 'dtls_server'
        elif (buf[app_offset+1] == 0xff and buf[app_offset+2] == 0x00 and
              buf[app_offset+3] == 0x00 and buf[app_offset+4] == 0x18):
                fp_str_, context_ = IQUIC.fingerprint(data, app_offset, data_len)
                fp_type = 'iquic'
        elif data_len - app_offset < 240:
            return None
        elif (buf[app_offset+236] == 0x63 and
              buf[app_offset+237] == 0x82 and
              buf[app_offset+238] == 0x53 and
              buf[app_offset+239] == 0x63):
            fp_str_, context_ = DHCP.fingerprint(data, app_offset, data_len)
            fp_type = 'dhcp'

    if fp_str_ == None:
        return None

    src_port = int.from_bytes(buf[prot_offset:prot_offset+2], byteorder='big')
    dst_port = int.from_bytes(buf[prot_offset+2:prot_offset+4], byteorder='big')
    if ip_type == 4:
        o_ = prot_offset-8
        src_ip = f'{buf[o_]}.{buf[o_+1]}.{buf[o_+2]}.{buf[o_+3]}'
        o_ += 4
        dst_ip = f'{buf[o_]}.{buf[o_+1]}.{buf[o_+2]}.{buf[o_+3]}'
    else:
        o_ = prot_offset-32
        src_ip = (f'{buf[o_]:02x}{buf[o_+1]:02x}:{buf[o_+2]:02x}{buf[o_+3]:02x}:'
                  f'{buf[o_+4]:02x}{buf[o_+5]:02x}:{buf[o_+6]:02x}{buf[o_+7]:02x}:'
                  f'{buf[o_+8]:02x}{buf[o_+9]:02x}:{buf[o_+10]:02x}{buf[o_+11]:02x}:'
                  f'{buf[o_+12]:02x}{buf[o_+13]:02x}:{buf[o_+14]:02x}{buf[o_+15]:02x}')
        o_ += 16
        dst_ip = (f'{buf[o_]:02x}{buf[o_+1]:02x}:{buf[o_+2]:02x}{buf[o_+3]:02x}:'
                  f'{buf[o_+4]:02x}{buf[o_+5]:02x}:{buf[o_+6]:02x}{buf[o_+7]:02x}:'
                  f'{buf[o_+8]:02x}{buf[o_+9]:02x}:{buf[o_+10]:02x}{buf[o_+11]:02x}:'
                  f'{buf[o_+12]:02x}{buf[o_+13]:02x}:{buf[o_+14]:02x}{buf[o_+15]:02x}')

    flow = {'src_ip':src_ip,
            'dst_ip':dst_ip,
            'src_port':src_port,
            'dst_port':dst_port,
            'protocol':protocol,
            'event_start':ts,
            'fingerprints': {}}
    if fp_type != 'server_certs':
        flow['fingerprints'][fp_type] = fp_str_
    else:
        if 'tls' not in flow:
            flow['tls'] = {}
        flow['tls'][fp_type] = fp_str_

    if context_ != None and context_ != []:
        flow[fp_type] = {}
        for x_ in context_:
            flow[fp_type][x_['name']]  = x_['data']

    if fp_str_2_ != None:
        if fp_type_2 != 'server_certs':
            flow['fingerprints'][fp_type_2] = fp_str_2_
        else:
            if 'tls' not in flow:
                flow['tls'] = {}
            flow['tls'][fp_type_2] = fp_str_2_

        if context_2_ != None and context_2_ != []:
            flow[fp_type_2] = {}
            for x_ in context_2_:
                flow[fp_type_2][x_['name']]  = x_['data']

    return flow
