#cython: language_level=3, wraparound=False, cdivision=True, infer_types=True, initializedcheck=False, c_string_type=bytes, embedsignature=False, nonecheck=False

"""
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

from pmercury.protocols.tcp import TCP
from pmercury.protocols.tls import TLS
from pmercury.protocols.http import HTTP
from pmercury.protocols.tls_server import TLS_Server
from pmercury.protocols.http_server import HTTP_Server

from pmercury.protocols.dhcp import DHCP


from cython.operator cimport dereference as deref
from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t

cdef extern from "arpa/inet.h":
    uint16_t htons(uint16_t hostshort)


def pkt_proc(double ts, bytes data):
    cdef uint8_t *buf = data

    cdef uint16_t ip_type = 4
    cdef uint16_t ip_length, ip_offset, protocol

    if buf[12] == 0x08 and buf[13] == 0x00: # IPv4
        ip_length = 20
        ip_offset = 14
        protocol = buf[23]
    elif buf[12] == 0x86 and buf[13] == 0xdd: # IPv6
        ip_type = 6
        ip_length = 40
        ip_offset = 14
        protocol = buf[20]
    elif buf[14] == 0x08 and buf[15] == 0x00: # IPv4 (hack for linux cooked capture)
        ip_length = 20
        ip_offset = 16
        protocol = buf[25]
    else: # currently skip other types
        return None

    cdef uint16_t data_len
    cdef uint16_t src_port, dst_port
    cdef uint16_t prot_length, prot_offset, app_offset
    cdef str fp_str_, fp_type, src_ip, dst_ip
    cdef list context_
    cdef dict flow

    data_len = len(data)
    fp_str_ = None
    if protocol == 6:
        prot_offset = ip_offset+ip_length
        if prot_offset+20 > data_len:
            return None
        prot_length = (buf[prot_offset+12] >> 0x04)*4
        app_offset = prot_offset + prot_length
        if buf[prot_offset+13] == 2:
            fp_str_, context_ = TCP.fingerprint(data, prot_offset, app_offset)
            fp_type = 'tcp'
        elif data_len - app_offset < 16:
            return None
        elif (buf[app_offset] == 22 and buf[app_offset+1] == 3 and buf[app_offset+9] == 3):
            if buf[app_offset+5]  ==  1:
                fp_str_, context_ = TLS.fingerprint(data, app_offset, data_len)
                fp_type = 'tls'
            elif buf[app_offset+5]  ==  2:
                fp_str_, context_ = TLS_Server.fingerprint(data, app_offset, data_len)
                fp_type = 'tls_server'
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
        if data_len - app_offset < 240:
            return None
        elif (buf[app_offset+236] == 0x63 and 
              buf[app_offset+237] == 0x82 and
              buf[app_offset+238] == 0x53 and
              buf[app_offset+239] == 0x63):
            fp_str_, context_ = DHCP.fingerprint(data, app_offset, data_len)
            fp_type = 'dhcp'

    if fp_str_ == None:
        return None

    src_port = htons(deref(<uint16_t *>(buf+prot_offset)))
    dst_port = htons(deref(<uint16_t *>(buf+prot_offset+2)))
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
            'fingerprints':{fp_type: fp_str_}}

    if context_ != None and context_ != []:
        flow[fp_type] = {}
        for x_ in context_:
            flow[fp_type][x_['name']]  = x_['data']

    return flow
