"""
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import os
import sys
import ast
import json

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from pmercury.utils.tls_constants import *
from pmercury.utils.pmercury_utils import *

grease_ = set(['0a0a','1a1a','2a2a','3a3a','4a4a','5a5a','6a6a','7a7a',
               '8a8a','9a9a','aaaa','baba','caca','dada','eaea','fafa'])

grease_single_int_ = set([10,26,42,58,74,90,106,122,138,154,170,186,202,218,234,250])

ext_data_extract_ = set(['0001','0005','0007','0008','0009','000a','000b',
                         '000d','000f','0010','0011','0013','0014','0018',
                         '001b','001c','002b','002d','0032','5500'])
ext_data_extract_ = ext_data_extract_.union(grease_)


imp_date_cs_file = find_resource_path('resources/implementation_date_cs.json.gz')
imp_date_ext_file = find_resource_path('resources/implementation_date_ext.json.gz')
if os.name == 'nt':
    import gzip
    for line in gzip.open(imp_date_cs_file, 'r'):
        imp_date_cs_data = json.loads(line)
        break
    for line in gzip.open(imp_date_ext_file, 'r'):
        imp_date_ext_data = json.loads(line)
        break
else:
    for line in os.popen('zcat %s' % (imp_date_cs_file)):
        imp_date_cs_data = json.loads(line)
        break
    for line in os.popen('zcat %s' % (imp_date_ext_file)):
        imp_date_ext_data = json.loads(line)
        break


def extract_server_name(data, offset, data_len):
    if data_len - offset < 7:
        return 'None'
    sni_len = int.from_bytes(data[offset+5:offset+7], 'big')
    try:
        return data[offset+7:offset+7+sni_len].decode()
    except UnicodeDecodeError:
        return data[offset+7:offset+7+sni_len].hex()


def eval_fp_str_general(fp_str_):
    fp_str_ = '(%s)' % fp_str_
    fp_str_ = fp_str_.replace('(','["').replace(')','"]').replace('][','],[')
    new_str_ = fp_str_.replace('["[','[[').replace(']"]',']]')
    while new_str_ != fp_str_:
        fp_str_ = new_str_
        new_str_ = fp_str_.replace('["[','[[').replace(']"]',']]')
    return ast.literal_eval(fp_str_)


def eval_fp_str(fp_str_):
    fp_str_ = fp_str_
    t_ = fp_str_.split(')')
    version = t_[0][1:]
    cs      = t_[1][1:]
    tmp_ext = fp_str_[len(cs)+9:-1]
    tmp_ext = tmp_ext.split(')')
    ext     = [e_[1:] for e_ in tmp_ext[:-1]]
    return [version, cs, ext]


def get_version_from_str(version_str_, convert=True):
    if version_str_ in TLS_VERSION and convert:
        return TLS_VERSION[version_str_]
    else:
        return version_str_


def get_cs_from_str(cs_str_, convert=True):
    cs_l_ = []
    for i in range(0,len(cs_str_),4):
        cs_ = cs_str_[i:i+4]
        if cs_ in imp_date_cs_data and convert:
            cs_l_.append(imp_date_cs_data[cs_]['name'])
        else:
            cs_l_.append(cs_)
    return cs_l_


def get_ext_from_str(exts_, convert=True, mode='client'):
    ext_l_ = []
    for ext in exts_:
        if len(ext) == 0:
            break
        ext_type_ = ext[0:4]
        ext_type_str_kind = str(int(ext_type_,16))
        if ext_type_str_kind in imp_date_ext_data and convert:
            ext_type_ = imp_date_ext_data[ext_type_str_kind]['name']
        ext_data_ = ''
        if len(ext) > 4 and convert:
            ext_data_ = parse_extension_data(ext_type_, ext[4:], mode)
        elif len(ext) > 4:
            ext_data_ = ext[4:]

        ext_l_.append({ext_type_: ext_data_})

    return ext_l_


def get_implementation_date(cs_str_): # @TODO: add extension
    dates_ = set([])
    for i in range(0,len(cs_str_),4):
        cs_ = cs_str_[i:i+4]
        if cs_ in imp_date_cs_data:
            dates_.add(imp_date_cs_data[cs_]['date'])
    dates_ = list(dates_)
    dates_.sort()
    if len(dates_) > 0:
        return dates_[-1], dates_[0]
    else:
        return None, None


def parse_extension_data(ext_type, ext_data_, mode):
    ext_len = int(ext_data_[0:4],16)
    ext_data = ext_data_[4:]

    if ext_type == 'application_layer_protocol_negotiation':
        ext_data = parse_application_layer_protocol_negotiation(ext_data, ext_len)
    elif ext_type == 'signature_algorithms':
        ext_data = signature_algorithms(ext_data, ext_len)
    elif ext_type == 'status_request':
        ext_data = status_request(ext_data, ext_len)
    elif ext_type == 'ec_point_formats':
        ext_data = ec_point_formats(ext_data, ext_len)
    elif ext_type == 'key_share':
        ext_data = key_share_client(ext_data, ext_len)
    elif ext_type == 'psk_key_exchange_modes':
        ext_data = psk_key_exchange_modes(ext_data, ext_len)
    elif ext_type == 'supported_versions':
        if mode == 'client':
            ext_data = supported_versions(ext_data, ext_len)
        else:
            ext_data = supported_versions_server(ext_data, ext_len)
    elif ext_type == 'supported_groups':
        ext_data = supported_groups(ext_data, ext_len)

    return ext_data


# helper to parse/extract/skip single extension
def parse_extension(data, offset):
    tmp_ext_type = degrease_type_code(data, offset)
    fp_ext_ = tmp_ext_type
    offset += 2
    ext_len = int.from_bytes(data[offset:offset+2],'big')
    offset += 2
    tmp_ext_value = data[offset:offset+ext_len]
    if tmp_ext_type in ext_data_extract_:
        tmp_ext_value = degrease_ext_data(data, offset, tmp_ext_type, ext_len, tmp_ext_value)
        fp_ext_ += '%04x%s' % (ext_len, tmp_ext_value.hex())
    offset += ext_len

    return fp_ext_, offset, ext_len

# helper to normalize grease type codes
def degrease_type_code(data, offset):
    if data[offset] in grease_single_int_ and data[offset] == data[offset+1]:
        return '0a0a'
    else:
        return data[offset:offset+2].hex()


# helper to normalize grease within supported_groups and supported_versions
def degrease_ext_data(data, offset, ext_type, ext_length, ext_value):
    degreased_ext_value = b''
    if ext_type == '000a': # supported_groups
        degreased_ext_value += data[offset:offset+2]
        for i in range(2,ext_length,2):
            if len(data) >= offset+i+1 and data[offset+i] in grease_single_int_ and data[offset+i] == data[offset+i+1]:
                degreased_ext_value += b'\x0a\x0a'
            else:
                degreased_ext_value += data[offset+i:offset+i+2]
        return degreased_ext_value
    elif ext_type == b'002b': # supported_versions
        degreased_ext_value += data[offset:offset+1]
        for i in range(1,ext_length,2):
            if len(data) >= offset+i+1 and data[offset+i] in grease_single_int_ and data[offset+i] == data[offset+i+1]:
                degreased_ext_value += b'\x0a\x0a'
            else:
                degreased_ext_value += data[offset+i:offset+i+2]
        return degreased_ext_value

    return ext_value


def supported_groups(data, length):
    if len(data) < 2:
        return ''
    info = {}
    ext_len = int(data[0:4], 16)
    info['supported_groups_list_length'] = ext_len
    info['supported_groups'] = []
    offset = 4
    while offset < length*2:
        if int(data[offset:offset+4], 16) in TLS_SUPPORTED_GROUPS:
            info['supported_groups'].append(TLS_SUPPORTED_GROUPS[int(data[offset:offset+4], 16)])
        else:
            info['supported_groups'].append('Unknown Group (%i)' % int(data[offset:offset+4], 16))
        offset += 4

    return info


def supported_versions(data, length):
    if len(data) < 2:
        return ''
    info = {}
    ext_len = int(data[0:2], 16)
    info['supported_versions_list_length'] = ext_len
    info['supported_versions'] = []
    offset = 2
    while offset < length*2:
        tmp_data = data[offset:offset+4]
        if tmp_data in TLS_VERSION:
            info['supported_versions'].append(TLS_VERSION[tmp_data])
        else:
            info['supported_versions'].append('Unknown Version (%s)' % tmp_data)
        offset += 4

    return info


def supported_versions_server(data, length):
    if len(data) < 2:
        return ''
    info = {}
    tmp_data = data[:4]
    if tmp_data in TLS_VERSION:
        return TLS_VERSION[tmp_data]
    else:
        return 'Unknown Version (%s)' % tmp_data

    return info


def psk_key_exchange_modes(data, length):
    if len(data) < 2:
        return ''
    info = {}
    ext_len = int(data[0:2], 16)
    info['psk_key_exchange_modes_length'] = ext_len
    mode = int(data[2:4], 16)
    info['psk_key_exchange_mode'] = TLS_PSK_KEY_EXCHANGE_MODES[mode]

    return info


def key_share_client(data, length):
    if len(data) < 2:
        return ''
    info = {}
    ext_len = int(data[0:4], 16)
    info['key_share_length'] = ext_len
    info['key_share_entries'] = []
    offset = 4
    while offset < length*2:
        tmp_obj = {}
        tmp_data = data[offset:offset+4]
        tmp_obj['group'] = TLS_SUPPORTED_GROUPS[int(tmp_data,16)]
        tmp_obj['key_exchange_length'] = int(data[offset+4:offset+8], 16)
        tmp_obj['key_exchange'] = data[offset+8:offset+8+2*tmp_obj['key_exchange_length']]
        info['key_share_entries'].append(tmp_obj)
        offset += 8 + 2*tmp_obj['key_exchange_length']

    return info


def ec_point_formats(data, length):
    if len(data) < 2:
        return ''
    info = {}
    ext_len = int(data[0:2], 16)
    info['ec_point_formats_length'] = ext_len
    info['ec_point_formats'] = []
    for i in range(ext_len):
        tmp_data = data[2*i+2:2*i+4]
        if tmp_data in TLS_EC_POINT_FORMATS:
            info['ec_point_formats'].append(TLS_EC_POINT_FORMATS[tmp_data])
        else:
            info['ec_point_formats'].append(tmp_data)

    return info


def status_request(data, length):
    if len(data) < 2:
        return ''
    info = {}
    info['certificate_status_type'] = TLS_CERTIFICATE_STATUS_TYPE[data[0:2]]
    offset = 2
    info['responder_id_list_length'] = int(data[offset:offset+4], 16)
    offset += info['responder_id_list_length']*2 + 4
    info['request_extensions_length'] = int(data[offset:offset+4], 16)

    return info


def signature_algorithms(data, length):
    if len(data) < 2:
        return ''
    info = {}
    ext_len = int(data[0:4], 16)
    info['signature_hash_algorithms_length'] = ext_len
    info['algorithms'] = []
    offset = 4
    while offset < length*2:
        tmp_data = data[offset:offset+4]
        if tmp_data in TLS_SIGNATURE_HASH_ALGORITHMS:
            info['algorithms'].append(TLS_SIGNATURE_HASH_ALGORITHMS[tmp_data])
        else:
            info['algorithms'].append('unknown(%s)' % tmp_data)
        offset += 4

    return info


def parse_application_layer_protocol_negotiation(data, length):
    alpn_len = int(data[0:4], 16)
    alpn_offset = 4
    alpn_data = []
    while alpn_offset < length*2:
        tmp_alpn_len = int(data[alpn_offset:alpn_offset+2], 16)
        alpn_offset += 2
        alpn_data.append(bytes.fromhex(data[alpn_offset:alpn_offset+2*tmp_alpn_len]).decode())
        alpn_offset += tmp_alpn_len*2

    return alpn_data


def get_tls_params(fp_):
    cs_ = []
    for i in range(0,len(fp_[1][0]),4):
        cs_.append(fp_[1][0][i:i+4])
    cs_4_ = get_ngram(cs_, 4)

    ext_ = []
    if len(fp_) > 2 and fp_[2] != ['']:
        for t_ext_ in fp_[2]:
            ext_.append('ext_' + t_ext_[0][0:4] + '::' + t_ext_[0][4:])

    return [cs_4_, ext_]


def get_sequence(fp_):
    seq = []
    cs_ = fp_[1][0]
    for i in range(0,len(cs_),4):
        seq.append(cs_[i:i+4])
    ext_ = []
    if len(fp_) > 2 and fp_[2] != ['']:
        for t_ext_ in fp_[2]:
            seq.append('ext_' + t_ext_[0][0:4] + '::' + t_ext_[0][4:])
    return seq


def get_ngram(l, ngram):
    l_ = []
    for i in range(0,len(l)-ngram):
        s_ = ''
        for j in range(ngram):
            s_ += l[i+j]
        l_.append(s_)
    if len(l_) == 0:
        l_ = l
    return l_





