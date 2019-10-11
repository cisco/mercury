import os
import sys
import dpkt
from binascii import hexlify, unhexlify

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from protocol import Protocol


class HTTP_Server(Protocol):

    def __init__(self, fp_database=None):
        # populate fingerprint databases
        self.fp_db = {}
        self.versions = set([b'HTTP/1.1',b'HTTP/1.0',b'HTTP/0.9'])
        self.case_insensitive_static_headers = set([b'access-control-allow-headers',b'access-control-allow-methods',
                                                    b'connection',b'content-encoding',b'pragma',b'referrer-policy',
                                                    b'server',b'strict-transport-security',b'vary',b'version',b'x-cache',
                                                    b'x-powered-by',b'x-xss-protection'])
        self.case_sensitive_static_headers = set([])
        self.headers_data = [0,1,2]
        self.contextual_data = {b'via':'via'}


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
        if t_.lower() in self.case_insensitive_static_headers:
            return hexlify(h_)
        if t_ in self.case_sensitive_static_headers:
            return hexlify(h_)
        return hexlify(t_)


    def extract_fingerprint(self, data):
        t_ = data.split(b'\r\n', 1)
        response = t_[0].split()
        if len(response) < 3:
            return None, None

        c = []
        for rh in self.headers_data:
            c.append(b'%s%s%s' % (b'(', hexlify(response[rh]), b')'))

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
        fp_h = [{'version':t_[0]},{'code':t_[1]},{'response':t_[2]}]
        for i in range(3, len(t_)-1):
            field = t_[i].split(': ')
            fp_h.append({field[0]: field[1]})
        return fp_h
