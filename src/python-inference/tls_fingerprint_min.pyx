#cython: language_level=3, wraparound=False, cdivision=True, infer_types=True, initializedcheck=False, c_string_type=bytes, embedsignature=False

import os
import bz2
import gzip
import json
import pyasn
import pickle
import functools
from collections import defaultdict

from libc.stdlib cimport malloc
from libc.math cimport exp, log, fmax
from libc.string cimport memcpy, strlen, strcpy

cdef long MAX_CACHED_RESULTS = 2**32

cdef constant_factory(str value):
        return lambda: value
port_mapping = defaultdict(constant_factory('unknown'), {443: 'https',448 :'database',465:'email',
                                                         563:'nntp',585:'email',614:'shell',636:'ldap',
                                                         989:'ftp',990:'ftp',991:'nas',992:'telnet',
                                                         993:'email',994:'irc',995:'email',1443:'alt-https',
                                                         2376:'docker',8001:'tor',8443:'alt-https',
                                                         9000:'tor',9001:'tor',9002:'tor',9101:'tor'})


cdef set tlds = set([])
public_suffix_file = os.path.dirname(os.path.abspath(__file__)) + '/../resources/public_suffix_list.dat.gz'
for line in os.popen('zcat %s' % (public_suffix_file)):
    line = str(line.strip())
    if line.startswith('//') or line == '':
        continue
    if line.startswith('*'):
        line = line[2:]
    tlds.add(line)


pyasn_context_file = os.path.dirname(os.path.abspath(__file__)) + '/../resources/pyasn.db.gz'
as_context_file = os.path.dirname(os.path.abspath(__file__)) + '/../resources/asn_info.db.gz'
pyasn_contextual_data = pyasn.pyasn(pyasn_context_file)
as_contextual_data = {}
for line in os.popen('zcat %s' % (as_context_file)):
    t_ = line.split()
    as_contextual_data[int(t_[0])] = t_[1]


cdef dict fp_db_detection = {}
cdef bint MALWARE_DB = True
db_filename = os.path.dirname(os.path.abspath(__file__)) + '/../resources/fingerprint_db.json.gz'
for line in os.popen('zcat %s' % (db_filename)):
    fp_ = json.loads(line)
    fp_['str_repr'] = bytes(fp_['str_repr'].replace('()',''),'utf-8')
    for p_ in fp_['process_info']:
        p_['process'] = bytes(p_['process'],'utf-8')
        if 'malware' not in p_:
            MALWARE_DB = False
    fp_db_detection[fp_['str_repr']] = fp_



cdef public api void process_identification_embed(char **r, const char *fp_str_, const char *server_name_,
                                                  const char *dest_addr_, int dest_port):
    tmp_r =  process_identification_embed_(fp_str_, server_name_, dest_addr_, dest_port)

    cdef dict results_obj
    if MALWARE_DB:
        results_obj = {'process':str(tmp_r[0],'utf-8'),'score':tmp_r[1],'malware':tmp_r[2],'p_malware':tmp_r[3]}
    else:
        results_obj = {'process':str(tmp_r[0],'utf-8'),'score':tmp_r[1]}

    cdef bytes results_str = bytes(json.dumps(results_obj),'utf-8')

    r[0] = <char *>malloc((strlen(results_str)+1)*sizeof(char))
    strcpy(r[0], <char *>results_str)


cdef tuple process_identification_embed_(const char *fp_str_, const char *server_name_, const char *dest_addr_, int dest_port):
    if fp_str_ not in fp_db_detection or 'process_info' not in fp_db_detection[fp_str_]:
        if MALWARE_DB:
            return (b'Unknown', 0.0, 0, 0.0)
        else:
            return (b'Unknown', 0.0)

    cdef str server_name = str(server_name_,'utf-8')
    cdef str dest_addr = str(dest_addr_,'utf-8')
    cdef str domain_
    domain_, _ = get_tld_info(server_name)
    cdef str asn_ = get_asn_info(dest_addr)
    cdef str port_app_ = port_mapping[dest_port]

    cdef tuple result = identify_embed(fp_str_, asn_, domain_, port_app_)

    return result


@functools.lru_cache(maxsize=MAX_CACHED_RESULTS)
def identify_embed(bytes fp_str_, str asn, str domain, str port_app):
    cdef dict fp_
    cdef list procs_
    fp_ = fp_db_detection[fp_str_]
    procs_ = fp_db_detection[fp_str_]['process_info']


    cdef double base_prior_ = -18.42068 # log(1e-8)
    cdef double prior_      =  -4.60517 # log(1e-2)

    cdef double p_count
    cdef double prob_process_given_fp

    cdef dict p_classes_ip_as
    cdef dict p_classes_hostname_domains
    cdef dict p_classes_hostname_alexa
    cdef dict p_classes_port_applications

    cdef double score_ = 0.0
    cdef double score_sum_ = 0.0

    cdef double t0_
    cdef double t_

    cdef double fp_tc_ = fp_['total_count']

    cdef bint sec_mal = False
    cdef bint max_mal = False
    cdef double max_score = 0.0
    cdef char *max_proc = 'Unknown'
    cdef double sec_score = 0.0
    cdef char *sec_proc = 'Unknown'
    cdef double malware_prob = 0.0
    cdef int N = len(procs_)
    cdef dict p_
    for i in range(N):
        p_ = procs_[i]
        p_count = p_['count']
        prob_process_given_fp = p_count/fp_tc_

        p_classes_ip_as = p_['classes_ip_as']
        p_classes_hostname_domains = p_['classes_hostname_domains']
        p_classes_port_applications = p_['classes_port_applications']

        score_ = log(prob_process_given_fp)
        score_ = fmax(score_, base_prior_)*3

        if asn in p_classes_ip_as:
            t0_ = p_classes_ip_as[asn]
            t_  = log(t0_/p_count)
            score_ += fmax(t_, prior_)
        else:
            score_ += base_prior_

        if domain in p_classes_hostname_domains:
            t0_ = p_classes_hostname_domains[domain]
            t_  = log(t0_/p_count)
            score_ += fmax(t_, prior_)
        else:
            score_ += base_prior_

        if port_app in p_classes_port_applications:
            t0_ = p_classes_port_applications[port_app]
            t_  = log(t0_/p_count)
            score_ += fmax(t_, prior_)
        else:
            score_ += base_prior_

        score_ = exp(score_)
        score_sum_ += score_

        if MALWARE_DB:
            if p_['malware'] == True and score_ > 0.0:
                malware_prob += score_

            if score_ > max_score:
                sec_score = max_score
                sec_proc = max_proc
                sec_mal = max_mal
                max_score = score_
                max_proc = p_['process']
                max_mal = p_['malware']
            elif score_ > sec_score:
                sec_score = score_
                sec_proc = p_['process']
                sec_mal = p_['malware']
        else: # MALWARE_DB == False
            if score_ > max_score:
                max_score = score_
                max_proc = p_['process']

    if MALWARE_DB and max_proc == b'Generic DMZ Traffic' and sec_mal == False:
        max_proc = sec_proc

    if score_sum_ > 0.0:
        max_score /= score_sum_
        if MALWARE_DB:
            malware_prob /= score_sum_

    if MALWARE_DB:
        return (max_proc, max_score, max_mal, malware_prob)
    else:
        return (max_proc, max_score)


@functools.lru_cache(maxsize=MAX_CACHED_RESULTS)
def get_tld_info(str hostname):
    if hostname == None:
        return 'None', 'None'
    cdef list tokens_ = hostname.split('.')
    cdef int N = len(tokens_)
    cdef str tld_ = tokens_[N-1]
    cdef str tmp_tld_ = tld_
    cdef str domain_ = tld_
    cdef str tmp_domain_ = tld_
    if N > 1:
        domain_ = f'{tokens_[N-2]}.{domain_}'
        tmp_domain_ = f'{tokens_[N-2]}.{tmp_domain_}'
    for i in range(2,7):
        if N < i:
            return domain_, tld_
        if N > i:
            tmp_domain_ = f'{tokens_[N-(i+1)]}.{tmp_domain_}'
        tmp_tld_ = f'{tokens_[N-i]}.{tmp_tld_}'
        if tmp_tld_ in tlds:
            domain_ = tmp_domain_
            tld_ = tmp_tld_
    return domain_, tld_


@functools.lru_cache(maxsize=MAX_CACHED_RESULTS)
def get_asn_info(str ip_addr):
    cdef str asn
    asn_n,_ = pyasn_contextual_data.lookup(ip_addr)
    if asn_n != None:
        return as_contextual_data[asn_n]

    return 'unknown'
