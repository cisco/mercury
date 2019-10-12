import os
import sys
import dpkt
from binascii import hexlify, unhexlify

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from protocol import Protocol


class HTTP_Server(Protocol):

    def __init__(self, fp_database=None, config=None):
        # populate fingerprint databases
        self.fp_db = {}

        # configuration
        self.all_headers = False
        if config == None or 'http_server' not in config:
            self.case_insensitive_static_headers = set([b'access-control-allow-headers',b'access-control-allow-methods',
                                                        b'connection',b'content-encoding',b'pragma',b'referrer-policy',
                                                        b'server',b'strict-transport-security',b'vary',b'version',b'x-cache',
                                                        b'x-powered-by',b'x-xss-protection'])
            self.case_sensitive_static_headers = set([])
            self.headers_data = [0,1,2]
            self.contextual_data = {b'via':'via'}
        else:
            self.case_insensitive_static_headers = set([])
            self.case_sensitive_static_headers = set([])
            self.headers_data = []
            self.contextual_data = {}
            if 'case_insensitive_static_headers' in config['http_server']:
                if config['http_server']['case_insensitive_static_headers'] == ['*']:
                    self.all_headers = True
                self.case_insensitive_static_headers = set(config['http_server']['case_insensitive_static_headers'])
            if 'case_sensitive_static_headers' in config['http_server']:
                if config['http_server']['case_sensitive_static_headers'] == ['*']:
                    self.all_headers = True
                self.case_sensitive_static_headers = set(config['http_server']['case_sensitive_static_headers'])
            if 'preamble' in config['http_server']:
                if 'version' in config['http_server']['preamble']:
                    self.headers_data.append(0)
                if 'code' in config['http_server']['preamble']:
                    self.headers_data.append(1)
                if 'reason' in config['http_server']['preamble']:
                    self.headers_data.append(2)
                if '*' in config['http_server']['preamble']:
                    self.headers_data = [0,1,2]
            if 'context' in config['http_server']:
                for c in config['http_server']['context']:
                    self.contextual_data[c] = c.lower().replace('-','_')


    def fingerprint(self, data, offset, data_len):
        if (data[offset]   != 72 or
            data[offset+1] != 84 or
            data[offset+2] != 84 or
            data[offset+3] != 80 or
            data[offset+4] != 47 or
            data[offset+5] != 49):
            return None, None, None, None
        fp_str_, context = self.extract_fingerprint(data[offset:])
        return 'http_server', fp_str_, None, context


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
        response = t_[0].split(b' ',2)
        if len(response) < 2:
            return None, None

        c = []
        for rh in self.headers_data:
            try:
                c.append(b'%s%s%s' % (b'(', hexlify(response[rh]), b')'))
            except IndexError:
                c.append(b'()')

        if len(t_) == 1:
            fp_str = b''.join(c)
            return fp_str, None

        headers = t_[1].split(b'\r\n')
        if headers[0] == '':
            headers = headers[1:]
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
        fp_h = [{'version':t_[0]},{'code':t_[1]},{'response':t_[2]}]
        for i in range(3, len(t_)-1):
            field = t_[i].split(': ')
            if len(field) == 2:
                fp_h.append({field[0]: field[1]})
            else:
                fp_h.append({field[0]: ''})
        return fp_h
