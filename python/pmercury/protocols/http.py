import os
import sys
import dpkt
from binascii import hexlify, unhexlify

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from protocol import Protocol


class HTTP(Protocol):

    def __init__(self, fp_database=None):
        # populate fingerprint databases
        self.fp_db = {}
        self.methods = set([b'GET',b'HEAD',b'POST',b'PUT',b'DELETE',b'CONNECT',b'OPTIONS',b'TRACE',b'PATCH'])
        self.versions = set([b'HTTP/1.1',b'HTTP/1.0',b'HTTP/0.9'])


    def fingerprint(self, data):
        t_ = data.split(b'\r\n', 1)[0].split()
        if len(t_) == 3 and t_[0] in self.methods and t_[2] in self.versions:
            fp_str_ = self.extract_fingerprint(data)
            return 'http', fp_str_, None, None

        return None, None, None, None


    def extract_fingerprint(self, data):
        t_ = data.split(b'\r\n', 1)
        request = t_[0].split()
        headers = t_[1].split(b'\r\n')
        fp_str = b''

        for r_ in request:
            fp_str += b'(' + hexlify(r_) + b')'

        for h_ in headers:
            if h_ == b'':
                break
            fp_str += b'(' + hexlify(h_) + b')'

        return fp_str


    def get_human_readable(self, fp_str_):
        t_ = [str(unhexlify(x[1:]),'utf-8') for x in fp_str_.split(b')')[:-1]]
        fp_h = [{'method':t_[0]},{'uri':t_[1]},{'version':t_[2]}]
        for i in range(3, len(t_)-1):
            field = t_[i].split(': ',1)
            fp_h.append({field[0]: field[1]})
        return fp_h
