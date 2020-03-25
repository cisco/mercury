"""
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import os
import ast
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from pmercury.protocols.protocol import Protocol


class HTTP(Protocol):

    def __init__(self, fp_database=None, config=None):
        # populate fingerprint databases
        self.fp_db = {}

        # configuration
        HTTP.all_headers = False
        HTTP.all_headers_and_data = False
        if config == None or 'http' not in config:
            HTTP.static_names = set([b'accept-charset',b'accept-language',b'authorization',b'cache-control',b'host',
                                     b'if-modified-since',b'keep-alive',b'user-agent',b'x-flash-version',
                                     b'x-p2p-peerdist'])
            HTTP.static_names_and_values = set([b'upgrade-insecure-requests',b'dnt',b'connection',
                                                b'x-requested-with',b'accept-encoding',b'accept',b'dpr'])
            HTTP.headers_data = [0,2]
            HTTP.contextual_data = {b'user-agent':'user_agent',b'host':'host',b'x-forwarded-for':'x_forwarded_for',b'uri':'uri'}
        else:
            HTTP.static_names = set([])
            HTTP.static_names_and_values = set([])
            HTTP.headers_data = []
            HTTP.contextual_data = {}
            if 'static_names' in config['http']:
                if config['http']['static_names'] == ['*']:
                    HTTP.all_headers = True
                HTTP.static_names = set(map(lambda x: x.encode(), config['http']['static_names']))
            if 'static_names_and_values' in config['http']:
                if config['http']['static_names_and_values'] == ['*']:
                    HTTP.all_headers_and_data = True
                HTTP.static_names_and_values = set(map(lambda x: x.encode(), config['http']['static_names_and_values']))
            if 'preamble' in config['http']:
                if 'method' in config['http']['preamble']:
                    HTTP.headers_data.append(0)
                if 'uri' in config['http']['preamble']:
                    HTTP.headers_data.append(1)
                if 'version' in config['http']['preamble']:
                    HTTP.headers_data.append(2)
                if '*' in config['http']['preamble']:
                    HTTP.headers_data = [0,1,2]
            if 'context' in config['http']:
                for c in config['http']['context']:
                    HTTP.contextual_data[c.encode()] = c.lower().replace('-','_')


    @staticmethod
    def proto_identify(data, offset, data_len):
        if data_len-offset < 16:
            return False
        if (data[offset]   == 71 and
            data[offset+1] == 69 and
            data[offset+2] == 84 and
            data[offset+3] == 32):
            return True
        return False


    @staticmethod
    def fingerprint(data, offset, data_len):
        t_ = data[offset:].split(b'\x0d\x0a', 1)
        request = t_[0].split()
        if len(request) < 3:
            return None, None

        c = []
        for rh in HTTP.headers_data:
            c.append('(%s)' % request[rh].hex())

        if len(t_) == 1:
            return ''.join(c), None

        http_ah  = HTTP.all_headers
        http_ahd = HTTP.all_headers_and_data
        http_sn  = HTTP.static_names
        http_snv = HTTP.static_names_and_values
        http_ctx = HTTP.contextual_data
        context = []
        if b'uri' in http_ctx:
            try:
                context.append({'name':'uri', 'data':request[1].decode()})
            except UnicodeDecodeError:
                context.append({'name':'uri', 'data':request[1].hex()})
        headers = t_[1].split(b'\x0d\x0a')
        for h_ in headers:
            if h_ == b'':
                break
            t0_ = h_.split(b'\x3a\x20',1)[0]
            t0_lower = t0_.lower()

            h_c = ''
            if http_ahd:
                h_c = h_.hex()
            elif t0_lower in http_snv:
                h_c = h_.hex()
            elif t0_lower in http_sn:
                h_c = t0_.hex()
            elif http_ah:
                h_c = t0_.hex()

            if h_c != '':
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


    @staticmethod
    def fingerprint_old(data, offset, data_len):
        t_ = data[offset:].split(b'\x0d\x0a', 1)
        request = t_[0].split()
        if len(request) < 3:
            return None, None

        c = []
        for rh in HTTP.headers_data:
            c.append('(%s)' % request[rh].hex())

        if len(t_) == 1:
            return ''.join(c), None

        http_ah = HTTP.all_headers
        http_cish = HTTP.case_insensitive_static_headers
        http_cssh = HTTP.case_sensitive_static_headers
        http_ctx = HTTP.contextual_data
        headers = t_[1].split(b'\x0d\x0a')
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


    def normalize_str_repr(self, str_repr):
        fp_str = str_repr.replace(')(','","').replace('(','["').replace(')','"]')
        t_ = ast.literal_eval(fp_str)

        c = [f'({t_[0]})', f'({t_[1]})']
        http_ah  = HTTP.all_headers
        http_ahd = HTTP.all_headers_and_data
        http_sn  = HTTP.static_names
        http_snv = HTTP.static_names_and_values
        http_ctx = HTTP.contextual_data
        for h in t_[2:]:
            b_str = bytes.fromhex(h)
            t0_ = b_str.split(b'\x3a\x20',1)[0]
            t0_lower = t0_.lower()

            h_c = ''
            if http_ahd:
                h_c = b_str.hex()
            elif t0_lower in http_snv:
                h_c = b_str.hex()
            elif t0_lower in http_sn:
                h_c = t0_.hex()
            elif http_ah:
                h_c = t0_.hex()

            if h_c != '':
                c.append(f'({h_c})')

        return ''.join(c)



    def get_human_readable(self, fp_str_):
        t_ = [bytes.fromhex(x[1:]) for x in fp_str_.split(')')[:-1]]
        try:
            fp_h = [{'method':t_[0].decode()},{'version':t_[1].decode()}]
        except:
            fp_h = [{'method':t_[0].hex()},{'version':t_[1].hex()}]
        for i in range(2, len(t_)-1):
            field = t_[i].split(b': ',1)
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


    def proc_identify(self, fp_str_, context_, dst_ip, dst_port, list_procs=0, endpoint=None, approx=True, debug=None):
        return None


    def os_identify(self, fp_str_, list_oses=0):
        return None
