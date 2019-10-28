#cython: language_level=3, wraparound=False, cdivision=True, infer_types=True, initializedcheck=False, c_string_type=bytes, embedsignature=False

from socket import AF_INET, AF_INET6, inet_ntop, htons
from cython.operator cimport dereference as deref

from pmercury.protocols.tcp import TCP
from pmercury.protocols.tls import TLS
from pmercury.protocols.http import HTTP
from pmercury.protocols.tls_server import TLS_Server
from pmercury.protocols.http_server import HTTP_Server

from pmercury.protocols.dhcp import DHCP


def pkt_proc(double ts, bytes data):
    cdef unsigned char *buf = data
    cdef int ip_type = 4
    cdef str fp_str_
    cdef int ip_length, ip_offset, tcp_length, tcp_offset, udp_length, udp_offset, app_offset
    cdef int protocol, data_len
    cdef int src_port, dst_port
    cdef list context_
    cdef dict flow

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
        return None, None, None, None

    data_len = len(data)
    if protocol == 6:
        tcp_offset = ip_offset+ip_length
        if tcp_offset+20 > data_len:
            return None, None, None, None
        tcp_length = (buf[tcp_offset+12] >> 0x04)*4
        app_offset = tcp_offset + tcp_length

        fp_str_ = None
        if buf[tcp_offset+13] == 2:
            fp_str_, context_ = TCP.fingerprint(data, tcp_offset, tcp_length)
            fp_type = 'tcp'
        elif data_len - app_offset < 16:
            pass
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


        if fp_str_ != None:
            src_port = htons(deref(<unsigned short *>(buf+tcp_offset)))
            dst_port = htons(deref(<unsigned short *>(buf+tcp_offset+2)))
            if ip_type == 4:
                o_ = tcp_offset-8
                src_ip = inet_ntop(AF_INET, buf[o_:o_+4])
                o_ += 4
                dst_ip = inet_ntop(AF_INET, buf[o_:o_+4])
            else:
                o_ = tcp_offset-32
                src_ip = inet_ntop(AF_INET6, buf[o_:o_+16])
                o_ += 16
                dst_ip = inet_ntop(AF_INET6, buf[o_:o_+16])

            flow = {'src_ip':src_ip,
                    'dst_ip':dst_ip,
                    'src_port':src_port,
                    'dst_port':dst_port,
                    'protocol':protocol,
                    'event_start':ts,
                    'fingerprints':{fp_type: fp_str_}}

            return fp_str_, fp_type, context_, flow


    elif protocol == 17:
        udp_offset = ip_offset+ip_length
        udp_length = 8
        app_offset = udp_offset + udp_length

        fp_str_ = None
        if data_len - app_offset < 240:
            return None, None, None, None
        elif (buf[app_offset+236] == 0x63 and 
              buf[app_offset+237] == 0x82 and
              buf[app_offset+238] == 0x53 and
              buf[app_offset+239] == 0x63):
            fp_str_, context_ = DHCP.fingerprint(data, app_offset, data_len)
            fp_type = 'dhcp'

        if fp_str_ != None:
            src_port = htons(deref(<unsigned short *>(buf+udp_offset)))
            dst_port = htons(deref(<unsigned short *>(buf+udp_offset+2)))
            if ip_type == 4:
                o_ = udp_offset-8
                src_ip = inet_ntop(AF_INET, buf[o_:o_+4])
                o_ += 4
                dst_ip = inet_ntop(AF_INET, buf[o_:o_+4])
            else:
                o_ = udp_offset-32
                src_ip = inet_ntop(AF_INET6, buf[o_:o_+16])
                o_ += 16
                dst_ip = inet_ntop(AF_INET6, buf[o_:o_+16])

            flow = {'src_ip':src_ip,
                    'dst_ip':dst_ip,
                    'src_port':src_port,
                    'dst_port':dst_port,
                    'protocol':protocol,
                    'event_start':ts,
                    'fingerprints':{fp_type: fp_str_}}

            return fp_str_, fp_type, context_, flow

    return None, None, None, None
