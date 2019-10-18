"""     
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import os
import sys
import socket
from binascii import hexlify, unhexlify

# application layer protocol parsing imports
#from http2 import HTTP2
from pmercury.protocols.http import HTTP
from pmercury.protocols.http_server import HTTP_Server
from pmercury.protocols.http2 import HTTP2

# TLS helper classes
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from pmercury.utils.tls_utils import *
from pmercury.utils.tls_constants import *
from pmercury.utils.tls_crypto import TLS_CRYPTO


class TLS_Decrypt:
    def __init__(self, keyfile):
        self.secrets = {}
        self.data_cache = {}
        self.tls_sequence = {}
        self.tls13_handshake = {}
        self.session_metadata = {}

        self.http2 = HTTP2()
        self.http = HTTP()
        self.http_server = HTTP_Server()
        self.tls_crypto = TLS_CRYPTO()
        self.initialize_keys(keyfile)


    def initialize_keys(self, keyfile):
        if not os.path.isfile(keyfile):
            print('warning: key file does not yet exist')
            return

        # parse the sslkeylog file, handles TLS 1.2/1.3 formats
        with open(keyfile, 'r') as fp:
            for line in fp:
                self.process_key_line(line)

    def process_key_line(self, line):
        if line.startswith('#') or line.strip() == '':
            return
        tokens = line.strip().split()

        if len(tokens) < 3:
            return
        elif len(tokens[1]) != 64:
            return
        elif len(tokens[2]) != 96 and len(tokens[2]) != 64:
            return

        if tokens[1] not in self.secrets:
            self.secrets[tokens[1]] = {}

        if tokens[0] == 'CLIENT_RANDOM':
            self.secrets[tokens[1]]['master_secret'] = tokens[2]
        elif tokens[0] == 'CLIENT_HANDSHAKE_TRAFFIC_SECRET':
            self.secrets[tokens[1]]['client_handshake_secret'] = tokens[2]
        elif tokens[0] == 'SERVER_HANDSHAKE_TRAFFIC_SECRET':
            self.secrets[tokens[1]]['server_handshake_secret'] = tokens[2]
        elif tokens[0] == 'CLIENT_TRAFFIC_SECRET_0':
            self.secrets[tokens[1]]['client_traffic_secret'] = tokens[2]
        elif tokens[0] == 'SERVER_TRAFFIC_SECRET_0':
            self.secrets[tokens[1]]['server_traffic_secret'] = tokens[2]

        # TODO: handle TLS 1.3 resumption keys


    def proto_identify_ch(self, data, offset):
        if (data[offset]    == 22 and
            data[offset+1]  ==  3 and
            data[offset+2]  <=  3 and
            data[offset+5]  ==  1 and
            data[offset+9]  ==  3 and
            data[offset+10] <=  3):
            return True
        return False


    def client_hello(self, data, flow_key):
        # Parse TLS version
        if str(hexlify(data[4:6]),'utf-8') in TLS_VERSION:
            self.session_metadata[flow_key]['version'] = TLS_VERSION[str(hexlify(data[4:6]),'utf-8')]
        else:
            self.session_metadata[flow_key]['version'] = 'unknown (%s)' % (str(hexlify(data[4:6]),'utf-8'))

        # Parse ClientHello client_random
        self.session_metadata[flow_key]['client_random'] = str(hexlify(data[6:38]),'utf-8')
        offset = 38


    def server_hello(self, data, flow_key):
        # Parse ServerHello server_random
        self.session_metadata[flow_key]['server_random'] = str(hexlify(data[6:38]),'utf-8')
        offset = 38
        
        # Parse ServerHello session_id ...
        #   if this is not TLS 1.3
        session_id_length = data[offset]
        offset += 1
        if session_id_length != 0:
            offset += session_id_length

        # Parse ServerHello selected_cipher_suite
        if str(hexlify(data[offset:offset+2]),'utf-8') not in TLS_CIPHER_SUITE_NAMES:
            return
        self.session_metadata[flow_key]['selected_cipher_suite'] = TLS_CIPHER_SUITE_NAMES[str(hexlify(data[offset:offset+2]),'utf-8')]
        offset += 2

        # Parse ServerHello compression method ...
        offset += 1

        # Parse ServerHello extensions
        if len(data) < offset+1: # check for existence of extensions
            return 
        ext_total_len = int(hexlify(data[offset:offset+2]),16)
        offset += 2

        # parse/extract/skip extension type/length/values
        while ext_total_len > 0:
            if len(data[offset:]) == 0:
                return

            if int(hexlify(data[offset:offset+2]),16) == 16:
                alpn_len = data[offset+6]
                alpn_offset = offset+7
                alpn_data = data[alpn_offset:alpn_offset+alpn_len]
                self.session_metadata[flow_key]['application_layer_protocol'] = str(alpn_data,'utf-8')

            if int(hexlify(data[offset:offset+2]),16) == 43:
                self.session_metadata[flow_key]['version'] = 'TLS 1.3'

            tmp_fp_ext, offset, ext_len = parse_extension(data, offset)
            ext_total_len -= 4 + ext_len


    def application_data(self, data, flow_key, length):
        # Parse Application Data length
        record_length = int(hexlify(data[3:5]),16)

        if self.session_metadata[flow_key]['client_random'] not in self.secrets:
            return

        # Decrypt Application Data
        tmp_data, pad_length, auth_length = self.tls_crypto.decrypt(data[5:5+record_length], flow_key,
                                                                    self.cur_mode, self.session_metadata[flow_key],
                                                                    self.tls_sequence, self.secrets, self.tls13_handshake)
        if tmp_data == None or len(tmp_data) < 2:
            return

        # check if the message is an encrypted alert message
        if len(tmp_data) >= 2 and len(tmp_data) < 4:
            if tmp_data[0] in TLS_ALERT_LEVELS and tmp_data[1] in TLS_ALERT_DESCRIPTIONS:
                return

        # check if the message is an encrypted handshake message
        if tmp_data[0] in TLS_HANDSHAKE_MESSAGE_TYPES:
            if int(hexlify(tmp_data[1:4]),16) <= len(tmp_data):
                self.parse_encrypted_content_message(tmp_data, flow_key)
                return


        if 'application_layer_protocol' not in self.session_metadata[flow_key]:
            self.determine_alp(tmp_data, flow_key)
        if 'application_layer_protocol' in self.session_metadata[flow_key]:
            if self.session_metadata[flow_key]['application_layer_protocol'].startswith('http/1'):
                if self.cur_mode == 'client':
                    http_fp,_ = self.http.fingerprint(tmp_data, 0, len(tmp_data))
                    if http_fp != None:
                        return http_fp
                else:
                    http_fp,_ = self.http_server.fingerprint(tmp_data, 0, len(tmp_data))
                    if http_fp != None:
                        return http_fp
            elif self.session_metadata[flow_key]['application_layer_protocol'] == 'h2':
                h2_fp = self.http2.fingerprint(tmp_data, flow_key, self.cur_mode)
                if h2_fp != None:
                    return h2_fp


    # The ALPN was not in the ServerHello, use heuristics
    def determine_alp(self, data, flow_key):
        if b'HTTP/1.1' in data:
            self.session_metadata[flow_key]['application_layer_protocol'] = 'http/1.1'
        elif b'HTTP/1' in data:
            self.session_metadata[flow_key]['application_layer_protocol'] = 'http/1.0'
        elif b'HTTP/2.0' in data:
            self.session_metadata[flow_key]['application_layer_protocol'] = 'h2'
        else:
            self.session_metadata[flow_key]['application_layer_protocol'] = 'h2'


    def alert(self, data, flow_key):
        if int(hexlify(data[3:5]),16) > 2:
            tmp, pad_length, auth_length = self.tls_crypto.decrypt(data[5:5+flow['length']], self.session_metadata[flow_key], flow_key, self.cur_mode, self.session_metadata, self.tls_sequence, self.secrets, self.tls13_handshake)


    def encrypted_handshake_message(self, data, flow_key):
        record_length = int(hexlify(data[3:5]),16)

        # Decrypt Data
        tmp_data = None
        if self.session_metadata[flow_key]['client_random'] in self.secrets:
            tmp_data, pad_length, auth_length = self.tls_crypto.decrypt(data[5:5+record_length], flow_key, self.cur_mode, 
                                                                        self.session_metadata, self.tls_sequence,
                                                                        self.secrets, self.tls13_handshake)

        # Parse encrypted handshake message
        if tmp_data != None:
            self.parse_encrypted_content_message(tmp_data, flow_key)

    
    def parse_encrypted_content_message(self, data, flow_key):
        cur_flow_key = flow_key + self.cur_mode

        offset = 0
        while offset < len(data)-1:
            record_length = int(hexlify(data[offset+1:offset+4]),16)

            handshake_type = data[offset]
            if handshake_type not in TLS_HANDSHAKE_MESSAGE_TYPES:
                offset += 4 + record_length
                continue
            handshake_name = TLS_HANDSHAKE_MESSAGE_TYPES[handshake_type]
            if handshake_name == 'finished':
                self.tls13_handshake[cur_flow_key] = False
                if self.session_metadata[flow_key]['version'].startswith('TLS 1.3'):
                    self.tls_sequence[cur_flow_key] = 0
            offset += 4 + record_length


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

        key_1 = hexlify(b''.join([src_addr,dst_addr,src_port,dst_port,pr])).decode()
        key_2 = hexlify(b''.join([dst_addr,src_addr,dst_port,src_port,pr])).decode()
        if key_1 in self.session_metadata:
            return key_1, 'client'
        elif key_2 in self.session_metadata:
            return key_2, 'server'
        else:
            return key_1, 'client'


    def fingerprint(self, data, ip_offset, tcp_offset, app_offset, ip_type, ip_length, data_len):
        protocol_type = 'tls_decrypt_'
        fp_str_ = None
        if app_offset+12 >= data_len:
            return protocol_type, fp_str_, None
        flow_key, mode = self.get_flow_key(data, ip_offset, tcp_offset, ip_type, ip_length)
        self.cur_mode = mode
        cur_flow_key = flow_key + mode
        if flow_key not in self.session_metadata and self.proto_identify_ch(data, app_offset) == False:
            return protocol_type, fp_str_, None
        elif self.proto_identify_ch(data, app_offset):
            self.session_metadata[flow_key] = {}

        data = data[app_offset:]

        # check TLS version to limit possibility of parsing junk
        if str(hexlify(data[1:3]),'utf-8') not in TLS_VERSION or len(data) < 5:
            # keep state to deal with larger packets
            if flow_key+self.cur_mode in self.data_cache and self.data_cache[flow_key+self.cur_mode][2]:
                data = self.data_cache[flow_key+self.cur_mode][0] + data
                if len(data[5:]) < self.data_cache[flow_key+self.cur_mode][1]:
                    self.data_cache[flow_key+self.cur_mode][0] = data
                    return protocol_type, fp_str_, None
            else:
                return protocol_type, fp_str_, None

        seen_client_hello = False
        offset = 0
        while offset < len(data):
            # check TLS version to limit possibility of parsing junk
            if str(hexlify(data[offset+1:offset+3]),'utf-8') not in TLS_VERSION:
                if len(data[offset:]) < 5:
                    self.data_cache[flow_key+self.cur_mode] = [data[offset:],0,True]
                    return None, fp_str_, None
                # keep state to hopefully recover, most likely due to packet fragmentation
                if flow_key+self.cur_mode not in self.data_cache:
                    self.data_cache[flow_key+self.cur_mode] = [data[offset:],0,True]
                    return protocol_type, fp_str_, None
                else:
                    return protocol_type, fp_str_, None
            if len(data[offset:]) < 5:
                if flow_key+self.cur_mode not in self.data_cache:
                    self.data_cache[flow_key+self.cur_mode] = [data[offset:],0,True]
                else:
                    self.data_cache[flow_key+self.cur_mode][0] += data[offset:]
                return protocol_type, fp_str_, None
    
            record_length = int(hexlify(data[offset+3:offset+5]),16)
            if record_length > len(data[offset+5:]):
                self.data_cache[flow_key+self.cur_mode] = [data[offset:],record_length,True]
                offset += 5 + record_length
                continue
            else:
                self.data_cache[flow_key+self.cur_mode] = [b'',0,False]

            record_type = data[offset]
            if record_type not in TLS_RECORD_TYPES:
                offset += 5 + record_length
                continue


            record_name = TLS_RECORD_TYPES[record_type]
            if record_name == 'change_cipher_spec':
                self.session_metadata[flow_key][self.cur_mode + '_change_cipher_spec'] = 1
            elif record_name == 'handshake':
                # check for encrypted messages
                if (flow_key in self.session_metadata and 
                    self.cur_mode + '_change_cipher_spec' in self.session_metadata[flow_key]):
                    self.encrypted_handshake_message(data[offset:], flow_key)
                    offset += 5 + record_length
                    continue


                handshake_type = data[offset+5]
                if handshake_type not in TLS_HANDSHAKE_MESSAGE_TYPES:
                    offset += 5 + record_length
                    continue
                handshake_name = TLS_HANDSHAKE_MESSAGE_TYPES[handshake_type]
                if handshake_name == 'client_hello':
                    seen_client_hello = True
                    if flow_key not in self.session_metadata:
                        self.session_metadata[flow_key] = {}
                    self.session_metadata[flow_key]['seen_client_hello'] = 1
                    self.client_hello(data[offset+5:], flow_key)

                elif handshake_name == 'server_hello':
                    self.server_hello(data[offset+5:], flow_key)

                elif handshake_name == 'finished':
                    self.tls13_handshake[cur_flow_key] = False
                    if self.session_metadata[flow_key]['version'].startswith('TLS 1.3'):
                        self.tls_sequence[cur_flow_key] = 0

            elif record_name == 'application_data':
                fp_str_ = self.application_data(data[offset:], flow_key, record_length)
                if fp_str_ != None:
                    protocol_type += self.session_metadata[flow_key]['application_layer_protocol'].split('/')[0]
                    if mode == 'server':
                        protocol_type += '_' + mode

            offset += 5 + record_length


        if flow_key in self.session_metadata and 'seen_client_hello' in self.session_metadata[flow_key]:
            return protocol_type, fp_str_, None
        else:
            self.data_cache.pop(flow_key+self.cur_mode,None)
            self.tls_sequence.pop(flow_key+self.cur_mode,None)
            self.tls13_handshake.pop(flow_key+self.cur_mode,None)
            self.session_metadata.pop(flow_key,None)
            self.session_metadata.pop(flow_key+self.cur_mode,None)
            return protocol_type, fp_str_, None


    def get_human_readable(self, fp_str_):
        if fp_str_.startswith('(3a'):
            return self.http2.get_human_readable(fp_str_)
        else:
            return self.http.get_human_readable(fp_str_)


