"""
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

from collections import OrderedDict
from binascii import hexlify, unhexlify

# http/2.0 imports
from hpack import Decoder

# constants
from utils.http2_constants import *

class HTTP2:
    def __init__(self):
        self.h2_decoder = {}
        self.data_cache = {}

    def fingerprint(self, data, flow_key, mode):
        flow_key += mode
        offset = 0
        data_offset = None

        if flow_key not in self.h2_decoder:
            self.h2_decoder[flow_key] = Decoder()
            self.h2_decoder[flow_key].max_allowed_table_size = 65536


        if flow_key in self.data_cache and self.data_cache[flow_key][2]:
            if self.data_cache[flow_key][0] + len(data) >= self.data_cache[flow_key][1]:
                data_offset = self.data_cache[flow_key][1] - self.data_cache[flow_key][0]
                self.data_cache[flow_key] = [0,0,False]
            else:
                self.data_cache[flow_key][0] += len(data)
                data_offset = None

        offset_ = self.check_magic(data)
        offset += offset_

        http2 = self.parse_iterate(data, offset, flow_key)
        if data_offset and http2 != None:
            http2 = self.parse_iterate(data, data_offset, flow_key)

        return http2

    def get_human_readable(self, fp_str_):
        t_ = [bytes.fromhex(x[1:]) for x in fp_str_.split(')')[:-1]]
        fp_h = []
        for i in range(len(t_)):
            field = t_[i].split(b': ',1)
            fp_h.append({field[0].decode(): field[1].decode()})
        return fp_h

    def parse_iterate(self, data, offset, flow_key):
        headers = None
        # go through http/2 messages
        while offset < len(data):
            msg = OrderedDict({})
            tmp_offset = offset

            # robustness check
            if len(data[offset:]) < 9:
                break

            # parse frame headers
            tmp_type = int(hexlify(data[offset+3:offset+4]),16)
            msg['length'] = int(hexlify(data[offset:offset+3]),16)
            msg['stream_identifier'] = int(hexlify(data[offset+5:offset+9]),16)

            # robustness against retransmissions, etc.
            if tmp_type not in HTTP2_MESSAGE_TYPES or \
               msg['stream_identifier'] > 1000 or \
               msg['length'] > 1000000:
                    break

            # success
            msg['type'] = HTTP2_MESSAGE_TYPES[tmp_type]
            self.parse_flags(data[offset+4], msg, msg['type'])
            offset += 9

            if msg['length'] > len(data[offset:]):
                self.data_cache[flow_key] = [len(data[offset:]),msg['length'],True]

            # Parse frame types
            if msg['type'] == 'DATA':
                self.parse_data(msg, data, offset)
            elif msg['type'] == 'HEADERS':
                headers = self.parse_headers(msg, data, offset, flow_key)
            elif msg['type'] == 'PRIORITY':
                self.parse_priority(msg, data, offset)
            elif msg['type'] == 'RST_STREAM':
                self.parse_rst_stream(msg, data, offset)
            elif msg['type'] == 'SETTINGS':
                self.parse_settings(msg, data, offset)
            elif msg['type'] == 'PING':
                self.parse_ping(msg, data, offset)
            elif msg['type'] == 'GOAWAY':
                self.parse_goaway(msg, data, offset)
            elif msg['type'] == 'WINDOW_UPDATE':
                self.parse_window_update(msg, data, offset)

            offset += msg['length']

        return headers


    def parse_headers(self, msg, data, offset, flow_key):
        # parse data associated with flags
        tmp_offset = 0
        if 'flags' in msg:
            if 'Padded' in msg['flags']:
                msg['pad_length'] = data[offset]
                offset += 1
                tmp_offset -= 1
            if 'Priority' in msg['flags']:
                tmp_dependency = int(hexlify(data[offset:offset+4]),16)
                msg['exclusive_stream_dependency'] = tmp_dependency & int('80000000',16)
                msg['depends_on_stream'] = tmp_dependency & int('7FFFFFFF',16)
                offset += 4
                msg['weight'] = int(hexlify(data[offset:offset+1]),16) + 1
                offset += 1
                tmp_offset -= 5

        # get just the data associated with the headers
        if 'pad_length' in msg:
            header_data = data[offset:msg['length']+offset+tmp_offset-msg['pad_length']]
        else:
            header_data = data[offset:msg['length']+offset+tmp_offset]

        # use hpack to parse headers
        try:
            headers = self.h2_decoder[flow_key].decode(header_data)
            msg['headers'] = []
            fp_str = b''
            for (header, value) in headers:
                fp_str += b'(' + hexlify(bytes(header,'utf-8')) +\
                          hexlify(b': ') + hexlify(bytes(value,'utf-8')) + b')'
                msg['headers'].append({header: value})
            return fp_str.decode()
        except:
            msg['status'] = 'failed to parse headers'
            msg['data'] = hexlify(header_data)


    def parse_data(self, msg, data, offset):
        # parse data associated with flags
        if 'flags' in msg and 'Padded' in msg['flags']:
            msg['pad_length'] = data[offset]
            offset += 1

        # parse body and store it as hex
        msg['body'] = hexlify(data[offset:])

    def parse_priority(self, msg, data, offset):
        if len(data[offset:]) < msg['length']:
            msg['priority'] = 'failure: no data'
            return

        # parse exclusive
        msg['exclusive'] = int(hexlify(data[offset:offset+4]),16) & int('80000000',16)

        # parse last stream id
        msg['stream_dependency'] = (int(hexlify(data[offset:offset+4]),16) << 1) >> 1

        # parse weight
        msg['weight'] = data[offset+4]

    def parse_rst_stream(self, msg, data, offset):
        # parse error code
        error_code = int(hexlify(data[offset:offset+4]),16)
        if error_code in HTTP2_ERROR_CODES:
            error_code = HTTP2_ERROR_CODES[error_code]
        else:
            error_code = 'unknown_error_code_%i' % error_code
        msg['error_code'] = error_code

    def parse_ping(self, msg, data, offset):
        # parse 8-bytes of PING data
        #  This data can be anything, but typically is all zeros
        msg['data'] = hexlify(data[offset:offset+8])

    def parse_settings(self, msg, data, offset):
        if len(data[offset:]) < msg['length']:
            msg['settings'] = 'failure: no data'
            return

        msg['settings'] = OrderedDict({})
        # settings format: 2 byte identifier, 4 byte value
        for i in range(0,msg['length'],6):
            s_type = int(hexlify(data[offset+i:offset+i+2]),16)
            if s_type in HTTP2_SETTINGS_TYPES:
                s_type = HTTP2_SETTINGS_TYPES[s_type]
            else:
                s_type = 'unknown_setting_%i' % s_type
            s_value = int(hexlify(data[offset+i+2:offset+i+6]),16)
            msg['settings'][s_type] = s_value

    def parse_goaway(self, msg, data, offset):
        # parse last stream id
        msg['last_stream_id'] = (int(hexlify(data[offset:offset+4]),16) << 1) >> 1

        # parse error code
        error_code = int(hexlify(data[offset+4:offset+8]),16)
        if error_code in HTTP2_ERROR_CODES:
            error_code = HTTP2_ERROR_CODES[error_code]
        else:
            error_code = 'unknown_error_code_%i' % error_code
        msg['error_code'] = error_code

        debug_data = hexlify(data[offset+8:offset+msg['length']])
        if len(debug_data) > 0:
            msg['debug_data'] = debug_data

    def parse_window_update(self, msg, data, offset):
        # parse the 31-bit window size increment
        if len(data[offset:]) < 4:
            msg['window_size_increment'] = 'failure: no data'
            return

        msg['window_size_increment'] = (int(hexlify(data[offset:offset+4]),16) << 1) >> 1

    def parse_flags(self, data, msg, frame_type):
        data = data
        if data == 0:
            return

        msg['flags'] = OrderedDict({})

        if frame_type == 'SETTINGS' or frame_type == 'PING':
            if data & 1:
                msg['flags']['Ack'] = True
        else:
            if data & 1:
                msg['flags']['End_Stream'] = True

        if data & 4:
            msg['flags']['End_Headers'] = True
        if data & 8:
            msg['flags']['Padded'] = True
        if data & 32:
            msg['flags']['Priority'] = True

    def check_magic(self, data):
        offset = 0

        # pre-defined string in the spec, seems to be a joke on PRISM
        if hexlify(data).startswith(b'505249202a20485454502f322e300d0a0d0a534d0d0a0d0a'):
            offset = 24

        return offset
