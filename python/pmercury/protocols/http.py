import os
import sys
import dpkt
from binascii import hexlify, unhexlify

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from protocol import Protocol


class HTTP(Protocol):

    def __init__(self, fp_database=None, config=None):
        # populate fingerprint databases
        self.fp_db = {}

        # configuration
        self.all_headers = False
        if config == None or 'http' not in config:
            self.case_insensitive_static_headers = set([b'upgrade-insecure-requests',b'dnt',b'accept-language',b'connection',
                                                        b'x-requested-with',b'accept-encoding',b'content-length',b'accept',
                                                        b'viewport-width',b'intervention',b'dpr',b'cache-control'])
            self.case_sensitive_static_headers = set([b'content-type',b'origin'])
            self.headers_data = [0,2]
            self.contextual_data = {b'user-agent':'user_agent',b'host':'host',b'x-forwarded-for':'x_forwarded_for'}
        else:
            self.case_insensitive_static_headers = set([])
            self.case_sensitive_static_headers = set([])
            self.headers_data = []
            self.contextual_data = {}
            if 'case_insensitive_static_headers' in config['http']:
                if config['http']['case_insensitive_static_headers'] == ['*']:
                    self.all_headers = True
                self.case_insensitive_static_headers = set(map(lambda x: x.lower().encode(), config['http']['case_insensitive_static_headers']))
            if 'case_sensitive_static_headers' in config['http']:
                if config['http']['case_sensitive_static_headers'] == ['*']:
                    self.all_headers = True
                self.case_sensitive_static_headers = set(map(lambda x: x.encode(), config['http']['case_sensitive_static_headers']))
            if 'preamble' in config['http']:
                if 'method' in config['http']['preamble']:
                    self.headers_data.append(0)
                if 'uri' in config['http']['preamble']:
                    self.headers_data.append(1)
                if 'version' in config['http']['preamble']:
                    self.headers_data.append(2)
                if '*' in config['http']['preamble']:
                    self.headers_data = [0,1,2]
            if 'context' in config['http']:
                for c in config['http']['context']:
                    self.contextual_data[c] = c.lower().replace('-','_')


    def fingerprint(self, data, offset, data_len):
        if (data[offset]   != 71 or
            data[offset+1] != 69 or
            data[offset+2] != 84 or
            data[offset+3] != 32):
            return None, None, None, None
        fp_str_, context = self.extract_fingerprint(data[offset:])
        return 'http', fp_str_, None, context


    def clean_header(self, h_, t_):
        if self.all_headers:
            return hexlify(h_)
        if t_.lower() in self.case_insensitive_static_headers:
            return hexlify(h_)
        if t_ in self.case_sensitive_static_headers:
            return hexlify(h_)
        return hexlify(t_)


    def extract_fingerprint(self, data):
        t_ = data.split(b'\r\n', 1)
        request = t_[0].split()
        if len(request) < 3:
            return None, None

        c = []
        for rh in self.headers_data:
            c.append(b'%s%s%s' % (b'(', hexlify(request[rh]), b')'))

        if len(t_) == 1:
            fp_str = b''.join(c)
            return fp_str, None

        headers = t_[1].split(b'\r\n')
        context = None
        for h_ in headers:
            if h_ == b'':
                break
            t0_ = h_.split(b': ',1)[0]
            c.append(b'%s%s%s' % (b'(', self.clean_header(h_, t0_), b')'))
            if t0_.lower() in self.contextual_data:
                if context == None:
                    context = []
                context.append({'name':self.contextual_data[t0_.lower()], 'data':h_.split(b': ',1)[1]})

        fp_str = b''.join(c)

        return fp_str, context


    def get_human_readable(self, fp_str_):
        t_ = [str(unhexlify(x[1:]),'utf-8') for x in fp_str_.split(b')')[:-1]]
        fp_h = [{'method':t_[0]},{'uri':t_[1]},{'version':t_[2]}]
        for i in range(3, len(t_)-1):
            field = t_[i].split(': ',1)
            if len(field) == 2:
                fp_h.append({field[0]: field[1]})
            else:
                fp_h.append({field[0]: ''})
        return fp_h
