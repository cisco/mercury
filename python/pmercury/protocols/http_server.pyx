#cython: language_level=3, wraparound=False, cdivision=True, infer_types=True, initializedcheck=False, c_string_type=bytes, embedsignature=False

"""
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from pmercury.protocols.protocol import Protocol


class HTTP_Server(Protocol):

    def __init__(self, fp_database=None, config=None):
        # populate fingerprint databases
        self.fp_db = {}

        # configuration
        HTTP_Server.all_headers = False
        if config == None or 'http_server' not in config:
            HTTP_Server.case_insensitive_static_headers = set([b'access-control-allow-headers',b'access-control-allow-methods',
                                                        b'connection',b'content-encoding',b'pragma',b'referrer-policy',
                                                        b'server',b'strict-transport-security',b'vary',b'version',b'x-cache',
                                                        b'x-powered-by',b'x-xss-protection'])
            HTTP_Server.case_sensitive_static_headers = set([])
            HTTP_Server.headers_data = [0,1,2]
            HTTP_Server.contextual_data = {b'via':'via'}
        else:
            HTTP_Server.case_insensitive_static_headers = set([])
            HTTP_Server.case_sensitive_static_headers = set([])
            HTTP_Server.headers_data = []
            HTTP_Server.contextual_data = {}
            if 'case_insensitive_static_headers' in config['http_server']:
                if config['http_server']['case_insensitive_static_headers'] == ['*']:
                    HTTP_Server.all_headers = True
                HTTP_Server.case_insensitive_static_headers = set(config['http_server']['case_insensitive_static_headers'])
            if 'case_sensitive_static_headers' in config['http_server']:
                if config['http_server']['case_sensitive_static_headers'] == ['*']:
                    HTTP_Server.all_headers = True
                HTTP_Server.case_sensitive_static_headers = set(config['http_server']['case_sensitive_static_headers'])
            if 'preamble' in config['http_server']:
                if 'version' in config['http_server']['preamble']:
                    HTTP_Server.headers_data.append(0)
                if 'code' in config['http_server']['preamble']:
                    HTTP_Server.headers_data.append(1)
                if 'reason' in config['http_server']['preamble']:
                    HTTP_Server.headers_data.append(2)
                if '*' in config['http_server']['preamble']:
                    HTTP_Server.headers_data = [0,1,2]
            if 'context' in config['http_server']:
                for c in config['http_server']['context']:
                    HTTP_Server.contextual_data[c.encode()] = c.lower().replace('-','_')


    @staticmethod
    def proto_identify(data, offset, data_len):
        if data_len-offset < 16:
            return False
        if (data[offset]   == 72 and
            data[offset+1] == 84 and
            data[offset+2] == 84 and
            data[offset+3] == 80 and
            data[offset+4] == 47 and
            data[offset+5] == 49):
            return True
        return False


    @staticmethod
    def fingerprint(bytes data, unsigned int offset, unsigned int data_len):
        cdef list t_ = data[offset:].split(b'\x0d\x0a', 1)
        cdef list response = t_[0].split(b'\x20',2)
        if len(response) < 2:
            return None, None

        cdef list c = []
        for rh in HTTP_Server.headers_data:
            try:
                c.append('(%s)' % response[rh].hex())
            except IndexError:
                c.append('()')

        if len(t_) == 1:
            return ''.join(c), None

        cdef list headers = t_[1].split(b'\x0d\x0a')
        if headers[0] == '':
            headers = headers[1:]
        cdef bint http_ah = HTTP_Server.all_headers
        cdef set http_cish = HTTP_Server.case_insensitive_static_headers
        cdef set http_cssh = HTTP_Server.case_sensitive_static_headers
        cdef dict http_ctx = HTTP_Server.contextual_data
        context = []
        for h_ in headers:
            if h_ == b'':
                break
            t0_ = h_.split(b'\x3a\x20',1)[0]
            t0_lower = t0_.lower()

            if http_ah:
                h_c = h_.hex()
            elif t0_lower in http_cish:
                h_c = h_.hex()
            elif t0_ in http_cssh:
                h_c = h_.hex()
            else:
                h_c = t0_.hex()

            c.append('(%s)' % h_c)
            if t0_lower in http_ctx:
                if b'\x3a\x20' in h_:
                    try:
                        context.append({'name':http_ctx[t0_lower], 'data':h_.split(b'\x3a\x20',1)[1].decode()})
                    except UnicodeDecodeError:
                        context.append({'name':http_ctx[t0_lower], 'data':h_.split(b'\x3a\x20',1)[1].hex()})
                else:
                    context.append({'name':http_ctx[t0_lower], 'data':''})

        return ''.join(c), context


    def get_human_readable(self, fp_str_):
        t_ = [bytes.fromhex(x[1:]) for x in fp_str_.split(')')[:-1]]
        try:
            fp_h = [{'version':t_[0].decode()},{'code':t_[1].decode()},{'response':t_[2].decode()}]
        except:
            fp_h = [{'version':t_[0].hex()},{'code':t_[1].hex()},{'response':t_[2].hex()}]
        for i in range(3, len(t_)-1):
            field = t_[i].split(b': ')
            if len(field) == 2:
                try:
                    fp_h.append({field[0].decode(): field[1].decode()})
                except:
                    fp_h.append({field[0].hex(): field[1].hex()})
            else:
                try:
                    fp_h.append({field[0].decode(): ''})
                except:
                    fp_h.append({field[0].hex(): ''})
        return fp_h
