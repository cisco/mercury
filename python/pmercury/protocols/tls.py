#!/usr/bin/env python3

"""     
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import os
import re
import sys
import gzip
import copy
import time
import struct
import operator
import functools
import ujson as json
from sys import path
from math import exp, log
from binascii import hexlify, unhexlify

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from protocol import Protocol
from utils.tls_utils import *
from utils.tls_constants import *
from utils.pmercury_utils import *
from utils.contextual_info import *
from utils.sequence_alignment import *

MAX_CACHED_RESULTS = 2**24


class TLS(Protocol):

    def __init__(self, fp_database=None):
        # cached data/results
        self.tls_params_db = {}

        # populate fingerprint databases
        self.fp_db = {}
        if fp_database == 'resources/fingerprint_db.json.gz':
            fp_database = find_resource_path(fp_database)
        if fp_database != None:
            self.load_database(fp_database)

        app_families_file = find_resource_path('resources/app_families.txt')
        self.app_families = {}
        for line in open(app_families_file, 'r'):
            tokens = line.strip().split(',')
            for i in range(1, len(tokens)):
                self.app_families[tokens[i]] = tokens[0]

        self.aligner = SequenceAlignment(f_similarity, 0.0)

        # TLS ClientHello pattern/RE
        self.pattern = b'\x16\x03[\x00-\x03].{2}\x01.{3}\x03[\x00-\x03]'


    def load_database(self, fp_database):
        for line in os.popen('zcat %s' % (fp_database)):
            fp_ = json.loads(line)
            fp_['str_repr'] = bytes(fp_['str_repr'],'utf-8')

            for p_ in fp_['process_info']:
                p_['process'] = bytes(p_['process'],'utf-8')

            self.fp_db[fp_['str_repr']] = fp_


    def fingerprint(self, data):
        # check TLS version and record/handshake type
        if re.findall(self.pattern, data[0:11], re.DOTALL) == []:
            return None, None, None, []

        # bounds checking
        record_length = int(hexlify(data[3:5]),16)
        if record_length != len(data[5:]):
            return None, None, None, []

        # extract fingerprint string
        fp_str_, server_name = self.extract_fingerprint(data[5:])
        fp_str_ = str(fp_str_)
        approx_str_ = None

        # fingerprint approximate matching if necessary
        fp_str_ = bytes(fp_str_,'utf-8')
        if fp_str_ not in self.fp_db:
            lit_fp = eval_fp_str(fp_str_)
            approx_str_ = self.find_approx_match(lit_fp)
            if approx_str_ == None:
                fp_ = self.gen_unknown_fingerprint(fp_str_)
                self.fp_db[fp_str_] = fp_
                return None, None, None, []
            self.fp_db[fp_str_] = self.fp_db[approx_str_]
            self.fp_db[fp_str_]['approx_str'] = approx_str_
        if 'approx_str' in self.fp_db[fp_str_]:
            approx_str_ = self.fp_db[fp_str_]['approx_str']

        return 'tls', fp_str_, approx_str_, [{'name':'server_name', 'data':server_name}]



    def proc_identify(self, fp_str_, context_, dest_addr, dest_port, list_procs=0):
        server_name = None
        if context_ != None:
            for x_ in context_:
                if x_['name'] == 'server_name':
                    server_name = x_['data']
                    break
        result = self.identify(fp_str_, server_name, dest_addr, dest_port, list_procs)

        return result


    @functools.lru_cache(maxsize=MAX_CACHED_RESULTS)
    def identify(self, fp_str_, server_name, dest_addr, dest_port, list_procs=0):
        fp_ = self.get_database_entry(fp_str_, None)
        if fp_ == None:
            return {'process': 'Unknown', 'score': 0.0}

        domain, tld = get_tld_info(server_name)
        asn = get_asn_info(dest_addr)
        port_app = get_port_application(dest_port)
        features = [asn, domain, port_app]

        fp_tc = fp_['total_count']
        r_ = [self.compute_score(features, p_, fp_tc) for p_ in fp_['process_info']]
        r_ = sorted(r_, key=operator.itemgetter('score'), reverse=True)

        if len(r_) == 0 or r_[0]['score'] == 0.0:
            predict_ = str(fp_['process_info'][0]['process'], 'utf-8')
            predict_ = self.app_families[predict_] if predict_ in self.app_families else predict_
            return {'process':predict_, 'score':0.0}

        process_name = str(r_[0]['process'], 'utf-8')
        process_name = self.app_families[process_name] if process_name in self.app_families else process_name

        score_sum_ = sum([x_['score'] for x_ in r_])
        
        out_ = {'process':process_name, 'score':r_[0]['score']}
        if list_procs > 0:
            r_proc_ = r_[0:list_procs]
            for p_ in r_proc_:
                p_['score'] /= score_sum_
            out_['probable_processes'] = r_proc_
        out_['score'] /= score_sum_

        return out_


    def compute_score(self, features, p_, fp_tc_):
        p_count = p_['count']
        prob_process_given_fp = log(p_count/fp_tc_)

        base_prior_ = -18.42068 # log(1e-8)
        prior_      =  -4.60517 # log(1e-2)

        score_ = prob_process_given_fp*3 if prob_process_given_fp > base_prior_ else base_prior_*3

        if features[0] in p_['classes_ip_as']:
            tmp_ = log(p_['classes_ip_as'][features[0]]/p_count)
            score_ += tmp_ if tmp_ > prior_ else prior_
        else:
            score_ += base_prior_

        if features[1] in p_['classes_hostname_domains']:
            tmp_ = log(p_['classes_hostname_domains'][features[1]]/p_count)
            score_ += tmp_ if tmp_ > prior_ else prior_
        else:
            score_ += base_prior_

        if features[2] in p_['classes_port_applications']:
            tmp_ = log(p_['classes_port_applications'][features[2]]/p_count)
            score_ += tmp_ if tmp_ > prior_ else prior_
        else:
            score_ += base_prior_

        return {'score':exp(score_), 'process':p_['process'], 'sha256':p_['sha256']}


    @functools.lru_cache(maxsize=MAX_CACHED_RESULTS)
    def get_database_entry(self, fp_str, approx_fp_str):
        fp_str_ = fp_str
        if approx_fp_str != None:
            fp_str_ = approx_fp_str
        
        if fp_str_ not in self.fp_db:
            return None

        return self.fp_db[fp_str_]


    def find_approx_match(self, tls_features, fp_str=None, source_filter=None, key_filter=None):
        target_ = get_sequence(tls_features)
        tls_params_ = get_tls_params(tls_features)

        t_sim_set = []
        approx_matches_set = self.find_approximate_matches_set(tls_params_, fp_str, source_filter, key_filter)
        for _,k in approx_matches_set:
            tmp_lit_fp = eval_fp_str(self.fp_db[k]['str_repr'])
            test_ = get_sequence(tmp_lit_fp)
            score_ = self.aligner.align(target_, test_)
            t_sim_set.append((1.0-2*score_/float(len(target_)+len(test_)), k))

        t_sim_set.sort()
        if len(t_sim_set) == 0:
            return None
        if t_sim_set[0][0] < 0.1:
            return t_sim_set[0][1]
        else:
            return None


    def find_approximate_matches_set(self, tls_params, fp_str=None, source_filter=None, key_filter=None):
        t_scores = []
        p0_ = set(tls_params[0])
        p1_ = set(tls_params[1])
        for k in self.fp_db.keys():
            k = k
            if source_filter != None and source_filter not in self.fp_db[k]['source']:
                continue
            if fp_str != None and key_filter != None and fp_str not in key_filter and k not in key_filter:
                continue
            if k not in self.tls_params_db:
                lit_fp = eval_fp_str(k)
                tls_params_ = get_tls_params(lit_fp)
                self.tls_params_db[k] = tls_params_
            q0_ = set(self.tls_params_db[k][0])
            q1_ = set(self.tls_params_db[k][1])
            s0_ = len(p0_.intersection(q0_))/max(1.0,len(p0_.union(q0_)))
            s1_ = len(p1_.intersection(q1_))/max(1.0,len(p1_.union(q1_)))
            s_ = s0_ + s1_
            t_scores.append((s_, k))
        t_scores.sort()
        t_scores.reverse()
        return t_scores[0:10]


    @functools.lru_cache(maxsize=MAX_CACHED_RESULTS)
    def gen_unknown_fingerprint(self, fp_str_):
        fp_ = {}
        fp_['str_repr'] = fp_str_
        lit_fp = eval_fp_str(fp_str_)
        if len(lit_fp) < 2 or len(lit_fp[1]) < 1:
            fp_['error'] = 'fingerprint string parsing error'
            return fp_
        max_imp, min_imp = get_implementation_date(lit_fp[1][0])
        fp_['max_implementation_date'] = max_imp
        fp_['min_implementation_date'] = min_imp
        fp_['total_count'] = 1
        fp_['tls_features'] = {}
        fp_['tls_features']['version'] = get_version_from_str(lit_fp[0][0])
        fp_['tls_features']['cipher_suites'] = get_cs_from_str(lit_fp[1][0])
        fp_['tls_features']['extensions'] = []
        if len(lit_fp) > 2:
            fp_['tls_features']['extensions'] = get_ext_from_str(lit_fp[2])
        fp_['process_info'] = [{'process': bytes('Unknown','utf-8'), 'sha256':'Unknown', 'count':1, 'malware': 0,
                                'classes_ip_as':{},'classes_hostname_tlds':{},'classes_hostname_domains':{},
                                'classes_port_applications':{},'os_info':{}}]

        return fp_


    def extract_fingerprint(self, data):
        # extract handshake version
        fp_ = data[4:6]

        # skip header/client_random
        offset = 38

        # parse/skip session_id
        session_id_length = int(hexlify(data[offset:offset+1]),16)
        offset += 1 + session_id_length
        if len(data[offset:]) == 0:
            return None, None

        # parse/extract/skip cipher_suites length
        cipher_suites_length = int(hexlify(data[offset:offset+2]),16)
        fp_ += data[offset:offset+2]
        offset += 2
        if len(data[offset:]) == 0:
            return None, None

        # parse/extract/skip cipher_suites
        cs_str_ = b''
        for i in range(0,cipher_suites_length,2):
            fp_ += degrease_type_code(data, offset+i)
            cs_str_ += degrease_type_code(data, offset+i)
        offset += cipher_suites_length
        if len(data[offset:]) == 0:
            return None, None

        # parse/skip compression method
        compression_methods_length = int(hexlify(data[offset:offset+1]),16)
        offset += 1 + compression_methods_length
        if len(data[offset:]) == 0:
            return hex_fp_to_structured_representation(hexlify(fp_)), None

        # parse/skip extensions length
        ext_total_len = int(hexlify(data[offset:offset+2]),16)
        offset += 2
        if len(data[offset:]) != ext_total_len:
            return None, None

        # parse/extract/skip extension type/length/values
        fp_ext_ = b''
        ext_fp_len_ = 0
        server_name = 'None'
        while ext_total_len > 0:
            if len(data[offset:]) == 0:
                return None, None

            # extract server name for process/malware identification
            if int(hexlify(data[offset:offset+2]),16) == 0:
                server_name = extract_server_name(data[offset+2:])

            tmp_fp_ext, offset, ext_len = parse_extension(data, offset)
            fp_ext_ += tmp_fp_ext
            ext_fp_len_ += len(tmp_fp_ext)

            ext_total_len -= 4 + ext_len

        fp_ += unhexlify(('%04x' % ext_fp_len_))
        fp_ += fp_ext_

        return hex_fp_to_structured_representation(hexlify(fp_)), server_name


    def get_human_readable(self, fp_str_):
        lit_fp = eval_fp_str(fp_str_)
        fp_h = OrderedDict({})
        fp_h['version'] = get_version_from_str(lit_fp[0][0])
        fp_h['cipher_suites'] = get_cs_from_str(lit_fp[1][0])
        fp_h['extensions'] = []
        if len(lit_fp) > 2:
            fp_h['extensions'] = get_ext_from_str(lit_fp[2])

        return fp_h
