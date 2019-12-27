#cython: language_level=3, wraparound=False, cdivision=True, infer_types=True, initializedcheck=False, c_string_type=bytes, embedsignature=False, nonecheck=False

"""
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import os
import sys
import json
import operator
import functools
from sys import path

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from pmercury.utils.tls_utils import *
from pmercury.utils.tls_constants import *
from pmercury.utils.pmercury_utils import *
from pmercury.utils.contextual_info import *
from pmercury.utils.sequence_alignment import *

from cython.operator cimport dereference as deref
from libc.math cimport exp, log, fmax
from libc.stdint cimport uint8_t, uint16_t, uint32_t, uint64_t

IF UNAME_SYSNAME == "Windows":
    cdef extern from "winsock2.h":
        uint16_t htons(uint16_t hostshort)
ELSE:
    cdef extern from "arpa/inet.h":
        uint16_t htons(uint16_t hostshort)

MAX_CACHED_RESULTS = 2**24


cdef class TLS():
    cdef bint MALWARE_DB
    cdef bint EXTENDED_FP_METADATA
    cdef dict tls_params_db
    cdef dict fp_db
    cdef dict app_families
    cdef dict transition_probs
    cdef object aligner

    def __init__(self, fp_database=None, config=None):
        # cached data/results
        self.tls_params_db = {}
        self.MALWARE_DB = True
        self.EXTENDED_FP_METADATA = False

        # populate fingerprint databases
        self.fp_db = {}
        if fp_database == 'resources/fingerprint_db.json.gz':
            fp_database = find_resource_path(fp_database)
        if fp_database != None:
            self.load_database(fp_database)

        IF UNAME_SYSNAME == "Windows":
            transition_probs_file = find_resource_path('resources/transition_probs.csv.gz')
            self.transition_probs = {}
            import gzip
            for line in gzip.open(transition_probs_file, 'r'):
                t_ = line.strip().split(b',')
                if t_[1].decode() not in self.transition_probs:
                    self.transition_probs[t_[1].decode()] = {}
                self.transition_probs[t_[1].decode()][t_[2].decode()] = float(t_[0])
        ELSE:
            transition_probs_file = find_resource_path('resources/transition_probs.csv.gz')
            self.transition_probs = {}
            for line in os.popen('zcat %s' % (transition_probs_file), mode='r', buffering=8192*256):
                t_ = line.strip().split(',')
                if t_[1] not in self.transition_probs:
                    self.transition_probs[t_[1]] = {}
                self.transition_probs[t_[1]][t_[2]] = float(t_[0])

        app_families_file = find_resource_path('resources/app_families.txt')
        self.app_families = {}
        for line in open(app_families_file, 'r'):
            tokens = line.strip().split(',')
            for i in range(1, len(tokens)):
                self.app_families[tokens[i]] = tokens[0]

        self.aligner = SequenceAlignment(f_similarity, 0.0)


    def load_database(self, str fp_database):
        cdef str line, fp_str
        cdef dict fp_
        IF UNAME_SYSNAME == "Windows":
            import gzip
            for line_win in gzip.open(fp_database, 'r'):
                fp_ = json.loads(line_win)
                self.fp_db[fp_['str_repr']] = fp_
        ELSE:
            for line in os.popen('zcat %s' % (fp_database), mode='r', buffering=8192*256):
                fp_ = json.loads(line)
                self.fp_db[fp_['str_repr']] = fp_
        if 'malware' not in self.fp_db[fp_['str_repr']]['process_info'][0]:
            self.MALWARE_DB = False
        if ('classes_ip_ip' in self.fp_db[fp_['str_repr']]['process_info'][0] and
            'classes_hostname_sni' in self.fp_db[fp_['str_repr']]['process_info'][0]):
            self.EXTENDED_FP_METADATA = True


    @staticmethod
    def proto_identify(data, offset, data_len):
        if data_len-offset < 16:
            return False
        if (data[offset]    == 22 and
            data[offset+1]  ==  3 and
            data[offset+2]  <=  3 and
            data[offset+5]  ==  1 and
            data[offset+9]  ==  3 and
            data[offset+10] <=  3):
            return True
        return False


    @staticmethod
    def fingerprint(bytes data, unsigned int offset, unsigned int data_len):
        cdef unsigned char *buf = data
        offset += 5

        # extract handshake version
        cdef list c = [f'({buf[offset+4]:02x}{buf[offset+5]:02x})']

        # skip header/client_random
        offset += 38

        # parse/skip session_id
        cdef uint8_t session_id_length = buf[offset]
        offset += 1 + session_id_length
        if offset >= data_len:
            return None, None

        # parse/extract/skip cipher_suites length
        cdef uint16_t cipher_suites_length = htons(deref(<uint16_t *>(buf+offset)))
        offset += 2
        if offset >= data_len:
            return None, None

        # parse/extract/skip cipher_suites
        cdef str cs_ = degrease_type_code(data, offset)
        if cipher_suites_length > 2:
            cs_ += buf[offset+2:offset+cipher_suites_length].hex()
        c.append('(%s)' % cs_)
        offset += cipher_suites_length
        if offset >= data_len:
            c.append('()')
            return ''.join(c), None

        # parse/skip compression method
        cdef uint8_t compression_methods_length = buf[offset]
        offset += 1 + compression_methods_length
        if offset >= data_len:
            c.append('()')
            return ''.join(c), None

        # parse/skip extensions length
        cdef uint16_t ext_total_len = htons(deref(<uint16_t *>(buf+offset)))
        offset += 2
        if offset >= data_len:
            c.append('()')
            return ''.join(c), None

        # parse/extract/skip extension type/length/values
        c.append('(')
        cdef str server_name = None
        cdef list context = None
        while ext_total_len > 0:
            if offset >= data_len:
                c.append(')')
                return ''.join(c), context

            # extract server name for process/malware identification
            if htons(deref(<uint16_t *>(buf+offset))) == 0:
                server_name = extract_server_name(data, offset+2, data_len)
                context = [{'name':'server_name', 'data':server_name}]

            tmp_fp_ext, offset, ext_len = parse_extension(data, offset)
            if ext_len+4 > ext_total_len:
                c.append(')')
                return ''.join(c), context
            c.append('(%s)' % tmp_fp_ext)

            ext_total_len -= 4 + ext_len
        c.append(')')

        return  ''.join(c), context


    def proc_identify(self, fp_str_, context_, dest_addr, dest_port, list_procs=0, endpoint=None):
        server_name = None
        # extract server_name field from context object
        if context_ != None and 'server_name' in context_:
            server_name = context_['server_name']

        # fingerprint approximate matching if necessary
        if fp_str_ not in self.fp_db:
            lit_fp = eval_fp_str(fp_str_)
            approx_str_ = self.find_approx_match(lit_fp)
            if approx_str_ == None:
                fp_ = self.gen_unknown_fingerprint(fp_str_)
                self.fp_db[fp_str_] = fp_
                if self.MALWARE_DB:
                    return {'process': 'Unknown', 'score': 0.0, 'malware': 0, 'p_malware': 0.0, 'category': 'Unknown'}
                else:
                    return {'process': 'Unknown', 'score': 0.0, 'category': 'Unknown'}
            self.fp_db[fp_str_] = self.fp_db[approx_str_]
            self.fp_db[fp_str_]['approx_str'] = approx_str_

        # perform process identification given the fingerprint string and destination information
        return self.identify(fp_str_, server_name, dest_addr, dest_port, list_procs, endpoint)


    @functools.lru_cache(maxsize=MAX_CACHED_RESULTS)
    def identify(self, fp_str_, server_name, dest_addr, dest_port, list_procs, endpoint=None):
        fp_ = self.get_database_entry(fp_str_, None)
        if fp_ == None:
            # if malware data is in the database, report malware scores
            if self.MALWARE_DB:
                return {'process': 'Unknown', 'score': 0.0, 'malware': 0, 'p_malware': 0.0, 'category': 'Unknown'}
            else:
                return {'process': 'Unknown', 'score': 0.0, 'category': 'Unknown'}

        # find generalized classes for destination information
        domain, tld = get_tld_info(server_name)
        asn = get_asn_info(dest_addr)
        port_app = get_port_application(dest_port)
        features = [asn, domain, port_app, dest_addr, str(server_name)]

        # compute and sort scores for each process in the fingerprint
        fp_tc = fp_['total_count']
        r_ = [self.compute_score(features, p_, fp_tc, endpoint) for p_ in fp_['process_info']]
        r_ = sorted(r_, key=operator.itemgetter('score'), reverse=True)

        # if score == 0 or no match could be found, return default process
        if len(r_) == 0 or r_[0]['score'] == 0.0:
            predict_ = fp_['process_info'][0]['process']
            predict_ = self.app_families[predict_] if predict_ in self.app_families else predict_
            if self.MALWARE_DB:
                return {'process':predict_, 'score': 0.0, 'malware': int(fp_['process_info'][0]['malware']),
                        'p_malware': 0.0, 'category': 'Unknown'}
            else:
                return {'process':predict_, 'score':0.0, 'category': 'Unknown'}

        # in the case of malware, remove pseudo process meant to reduce false positives
        if self.MALWARE_DB and r_[0]['malware'] == False and \
           r_[0]['process'] == 'Generic DMZ Traffic' and len(r_) > 1 and r_[1]['malware'] == False:
            r_.pop(0)

        # get generalized process name if available
        process_name = r_[0]['process']
        process_name = self.app_families[process_name] if process_name in self.app_families else process_name

        # package the most probable process
        score_sum_ = sum([x_['score'] for x_ in r_])
        if self.MALWARE_DB:
            malware_score_ = sum([x_['score'] for x_ in r_ if x_['malware'] == 1])/score_sum_
            out_ = {'process':process_name, 'score':r_[0]['score'], 'malware':int(r_[0]['malware']),
                    'p_malware':malware_score_, 'category':r_[0]['category']}
        else:
            out_ = {'process':process_name, 'score':r_[0]['score'], 'category':r_[0]['category']}

        # return the top-n most probable processes is list_procs > 0
        if list_procs > 0:
            r_proc_ = r_[0:list_procs]
            for p_ in r_proc_:
                p_['score'] /= score_sum_
            out_['probable_processes'] = r_proc_
        out_['score'] /= score_sum_

        return out_


    def compute_score(self, list features, dict p_, double fp_tc_, object endpoint):
        cdef str cur_proc       = p_['process']
        cdef uint64_t p_count     = p_['count']
        cdef double prob_process_given_fp = log(p_count/fp_tc_)

        cdef double base_prior_ = -27.63102 # log(1e-12)
        cdef double proc_prior_ = -11.51293 # log(1e-5)
        cdef double prior_      = -13.81551 # log(1e-6)

        cdef double score_ = prob_process_given_fp if prob_process_given_fp > proc_prior_ else proc_prior_
        cdef double tmp_, trans_prob, prev_proc_prior

        if endpoint != None and endpoint.prev_flow != None and 'analysis' in endpoint.prev_flow:
            trans_prob = sum([pp_['score']*self.transition_probs[pp_['process']][cur_proc]
                              for pp_ in endpoint.prev_flow['analysis']['probable_processes']
                              if pp_['process'] in self.transition_probs and cur_proc in self.transition_probs[pp_['process']]])
            prev_proc_prior = base_prior_
            if trans_prob > 0:
                prev_proc_prior = log(trans_prob)
            score_ += base_prior_ if base_prior_> prev_proc_prior else prev_proc_prior

        try:
            tmp_ = log(p_['classes_ip_as'][features[0]]/p_count)
            score_ += tmp_ if tmp_ > prior_ else prior_
        except KeyError:
            score_ += base_prior_

        try:
            tmp_ = log(p_['classes_hostname_domains'][features[1]]/p_count)
            score_ += tmp_ if tmp_ > prior_ else prior_
        except KeyError:
            score_ += base_prior_

        try:
            tmp_ = log(p_['classes_port_applications'][features[2]]/p_count)
            score_ += tmp_ if tmp_ > prior_ else prior_
        except KeyError:
            score_ += base_prior_

        if self.EXTENDED_FP_METADATA:
            try:
                tmp_ = log(p_['classes_ip_ip'][features[3]]/p_count)
                score_ += tmp_ if tmp_ > prior_ else prior_
            except KeyError:
                score_ += base_prior_

            try:
                tmp_ = log(p_['classes_hostname_sni'][features[4]]/p_count)
                score_ += tmp_ if tmp_ > prior_ else prior_
            except KeyError:
                score_ += base_prior_

        app_cat = 'Unknown'
        if 'application_category' in p_:
            app_cat = p_['application_category']

        if self.MALWARE_DB:
            return {'score':exp(score_), 'process':cur_proc, 'sha256':p_['sha256'],
                    'malware':p_['malware'], 'category':app_cat}
        else:
            return {'score':exp(score_), 'process':cur_proc, 'sha256':p_['sha256'], 'category':app_cat}


    @functools.lru_cache(maxsize=MAX_CACHED_RESULTS)
    def get_database_entry(self, fp_str, approx_fp_str):
        fp_str_ = fp_str
        if approx_fp_str != None:
            fp_str_ = approx_fp_str

        try:
            return self.fp_db[fp_str_]
        except KeyError:
            return None


    @functools.lru_cache(maxsize=MAX_CACHED_RESULTS)
    def get_approx_fingerprint(self, fp_str_):
        try:
            return self.fp_db[fp_str_]['approx_str']
        except KeyError:
            return None


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
            s0_ = len(p0_.intersection(q0_))/fmax(1.0,len(p0_.union(q0_)))
            s1_ = len(p1_.intersection(q1_))/fmax(1.0,len(p1_.union(q1_)))
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
        fp_['process_info'] = [{'process': 'Unknown', 'sha256':'Unknown', 'count':1, 'malware': 0,
                                'classes_ip_as':{},'classes_hostname_tlds':{},'classes_hostname_domains':{},
                                'classes_port_applications':{},'os_info':{}}]

        return fp_


    def get_human_readable(self, fp_str_):
        lit_fp = eval_fp_str(fp_str_)
        fp_h = {}
        fp_h['version'] = get_version_from_str(lit_fp[0])
        fp_h['cipher_suites'] = get_cs_from_str(lit_fp[1])
        fp_h['extensions'] = []
        if len(lit_fp) > 2:
            fp_h['extensions'] = get_ext_from_str(lit_fp[2])

        return fp_h
