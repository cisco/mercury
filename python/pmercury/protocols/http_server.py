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
    def fingerprint(data, offset, data_len):
        fp_str_, context = HTTP_Server.extract_fingerprint(data[offset:])

        return fp_str_, context


    @staticmethod
    def clean_header(h_, t_):
        if HTTP_Server.all_headers:
            return hexlify(h_)
        if t_.lower() in HTTP_Server.case_insensitive_static_headers:
            return hexlify(h_)
        if t_ in HTTP_Server.case_sensitive_static_headers:
            return hexlify(h_)
        return hexlify(t_)


    @staticmethod
    def extract_fingerprint(data):
        t_ = data.split(b'\r\n', 1)
        response = t_[0].split(b' ',2)
        if len(response) < 2:
            return None, None

        c = []
        for rh in HTTP_Server.headers_data:
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
            c.append(b'%s%s%s' % (b'(', HTTP_Server.clean_header(h_, t0_), b')'))
            if t0_.lower() in HTTP_Server.contextual_data:
                if context == None:
                    context = []
                context.append({'name':HTTP_Server.contextual_data[t0_.lower()], 'data':h_.split(b': ',1)[1]})

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
