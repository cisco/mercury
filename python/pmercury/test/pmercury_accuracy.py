#!/usr/bin/env python3


import os
import sys
import gzip
import json
import time
import optparse
import importlib
from importlib import machinery
from multiprocessing import Pool

sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../../')

from fp_constants import *

fingerprinter = None

app_families_file = '../../../resources/app_families.txt'
app_families = {}
for line in open(app_families_file, 'r'):
    tokens = line.strip().split(',')
    for i in range(1, len(tokens)):
        app_families[tokens[i]] = tokens[0]


app_families_strict_file = '../../../resources/app_families_strict.txt'
app_families_strict = {}
#for line in open(app_families_strict_file, 'r'):
#    tokens = line.strip().split(',')
#    for i in range(1, len(tokens)):
#        app_families_strict[tokens[i]] = tokens[0]

fp_sni_blacklist = set([])


class Validation:

    def __init__(self, in_file, fp_db_name, output, categories, top, blacklist, malware_ctx_file, proc_list):
        if output == sys.stdout:
            self.out_file_pointer = sys.stdout
        else:
            self.out_file_pointer = open(output, 'w')
        self.categories = categories
        self.top = top
        self.blacklist = blacklist
        self.malware_ctx = None
        if malware_ctx_file != None:
            self.malware_ctx = {}
            for line in gzip.open(malware_ctx_file):
                fp_ = json.loads(line)
                self.malware_ctx[fp_['str_repr']] = fp_

        self.proc_list = None
        if proc_list != None:
            self.proc_list = []
            t_ = proc_list.split(';')
            for s in t_:
                if s != '':
                    tmp_proc_list = s.split(',')
                    self.categories.append(tmp_proc_list[0])
                    self.proc_list.append(tmp_proc_list)

        # read in application categories
        app_cat_file = 'application_categories.json.gz'
        with gzip.open(app_cat_file,'r') as fp:
            self.app_cat_data = json.loads(fp.read())

        self.mt_pool = Pool(32)

        self.input_file = in_file
        if in_file.endswith('.csv.gz'):
            self.data = self.read_file_csv(in_file)
        elif in_file.endswith('.json.gz') and 'dmz' in in_file:
            self.data = self.read_file_dmz_json(in_file)
        elif in_file.endswith('.json.gz'):
            self.data = self.read_file_json(in_file)
        else:
            print('error: file format not supported')
            sys.exit(-1)


    def validate_process_identification(self):
        results = []
        unknown_fp = 0
        unknown_s  = 0

        if self.top:
            results = self.mt_pool.map(get_results_top, [self.data[k] for k in self.data])
        elif self.blacklist:
            results = self.mt_pool.map(get_results_blacklist, [self.data[k] for k in self.data])
        else:
            results = self.mt_pool.map(get_results, [self.data[k] for k in self.data])
#            for k in self.data:
#                results.append(get_results(self.data[k]))

        self.data = None

        self.analyze_results(results)


    def analyze_results(self, results):
        r_tmp_ = self.mt_pool.map(process_result, [(sl, self.categories) for sl in results])
        r_tmp_ = [x for sl in r_tmp_ for x in sl]
        r_ = [sum([row[i] for row in r_tmp_]) for i in range(0,len(r_tmp_[0][:-1]))]

        print('FILE: %s' % self.input_file)
        print('\tTotal:\t\t\t\t    % 8i' % r_[0])
        print('\t                              :\t      top-1    top-2    top-3    top-4    top-5')
        print('\tProcess Name Category Accuracy:\t    %0.6f %0.6f %0.6f %0.6f %0.6f' % (r_[2]/r_[0], (r_[2]+r_[5])/r_[0], (r_[2]+r_[5]+r_[7])/r_[0], (r_[2]+r_[5]+r_[7]+r_[9])/r_[0], (r_[2]+r_[5]+r_[7]+r_[9]+r_[11])/r_[0]))
        print('\tProcess Name Accuracy:\t\t    %0.6f %0.6f %0.6f %0.6f %0.6f' % (r_[1]/r_[0], (r_[1]+r_[4])/r_[0], (r_[1]+r_[4]+r_[6])/r_[0], (r_[1]+r_[4]+r_[6]+r_[8])/r_[0], (r_[1]+r_[4]+r_[6]+r_[8]+r_[9])/r_[0]))
#        print('\tSHA-256 Accuracy:\t\t    %0.6f' % (r_[3]/r_[0]))

        r_c = [row[-1] for row in r_tmp_]
        idx = 0
        for c in self.categories:
            if c == '':
                continue
            r_ = [sum([row[idx][i] for row in r_c]) for i in range(0,len(r_c[0][0]))]
            print('\n\t%s Accuracy:\t\t    %0.6f' % (c, (r_[1]/r_[0])))
            print('\t%s Confusion Matrix:' % c)
            print('\t\t\t   Positive       Negative')
            print('\t\tPositive:% 9i\t% 9i' % (r_[2], r_[5]))
            print('\t\tNegative:% 9i\t% 9i' % (r_[4], r_[3]))
            if r_[2]+r_[5] > 0:
                print('\t\tRecall:    %0.6f' % (r_[2]/(r_[2]+r_[5])))
            else:
                print('\t\tRecall:    %0.6f' % (0.0))
            if r_[2]+r_[4] > 0:
                print('\t\tPrecision: %0.6f' % (r_[2]/(r_[2]+r_[4])))
            else:
                print('\t\tPrecision: %0.6f' % (0.0))

            idx += 1


    def read_file_csv(self, f):
        data = {}

        max_lines = 30000000
        cur_line  = 0

        start = time.time()
        for line in os.popen('zcat %s' % (f)):
            cur_line += 1
            if cur_line > max_lines:
                break
#            if '(0000)' not in line:
#                continue
            t_          = line.strip().split(',')
            src         = t_[0]
            proc        = t_[3]
            sha256      = t_[4]
            type_       = t_[5]
            fp_str      = t_[6].replace('()','')
            dst_x       = t_[7].split(')')
            os_         = clean_os_str(t_[8])
            if os_ == None:
                continue

            dst_ip      = dst_x[0][1:]
            dst_port    = int(dst_x[1][1:])
            server_name = dst_x[2][1:]
            src_port    = int(t_[9].split(')')[1][1:])
            av_hits     = 0
            if len(t_) > 10:
                av_hits = int(t_[10])

            proc = clean_proc_name(proc)

            if proc in uninformative_proc_names:
                continue

            fp_malware_ = False
            if self.malware_ctx != None:
                if fp_str in self.malware_ctx:
                    fp_malware_ = is_fp_malware(self.malware_ctx[fp_str])
                else:
                    continue

            app_cat = None
            if proc in self.app_cat_data:
                app_cat = self.app_cat_data[proc]
            malware = is_proc_malware({'process':proc}, fp_malware_, av_hits)
            domain = server_name
            sni_split = server_name.split('.')
            if len(sni_split) > 1:
                domain = sni_split[-2] + '.' + sni_split[-1]
            if server_name in sni_whitelist or domain in domain_whitelist:
                malware = False
            app_cats = {}
            app_cats['malware'] = malware
            for c in self.categories:
                if c == 'malware':
                    app_cats[c] = malware
                else:
                    app_cats[c] = False
                    if c == app_cat:
                        app_cats[c] = True

            if os_ == None:
                continue

            if src not in data:
                data[src] = []

            data[src].append((src,src_port,proc,sha256,type_,fp_str,dst_ip,dst_port,server_name,1,os_,app_cats, self.proc_list))

        print('time to read data:\t%0.2f' % (time.time()-start))

        return data


    def read_file_json(self, f):
        data = {}

        start = time.time()
        key_ = 0
        data[key_] = []
        for line in os.popen('zcat %s' % (f)):
            fp_ = json.loads(line)
            if 'str_repr' in fp_:
                fp_str = fp_['str_repr']
            else:
                fp_str = fp_['md5']
#            if fp_str in schannel_fps:
#                fp_str = 'schannel'

#            if fp_str != '(0301)(c014c013c00ac0090035002f00380032000a001300050004)((0000)(000a00080006001900170018)(000b00020100)(ff01))':
#            if fp_str != '(0303)(c02cc030009fcca9cca8ccaac02bc02f009ec024c028006bc023c0270067c00ac0140039c009c0130033009d009c003d003c0035002f00ff)((000b000403000102)(000a000a0008001d001700190018)(0023)(000d0020001e060106020603050105020503040104020403030103020303020102020203)(0016)(0017))':
#                continue

            if 'process_info' in fp_:
                new_procs = []
                fp_malware_ = is_fp_malware(fp_)
                for p_ in fp_['process_info']:
                    if 'process' not in p_:
                        p_['process'] = p_['filename']
#                    if self.proc_list != None and p_['process'].lower() not in self.proc_list:
#                        continue
                    p_['process'] = clean_proc_name(p_['process'])
                    if is_proc_malware(p_, fp_malware_):
                        new_procs.extend(clean_malware_proc(p_))
                    else:
                        new_procs.append(p_)
                fp_['process_info'] = new_procs


                for p_ in fp_['process_info']:
#                    if self.proc_list != None and p_['process'].lower() not in self.proc_list:
#                        continue
                    proc = p_['process']
                    sha256 = p_['sha256']

                    if p_['process'] in uninformative_proc_names:
                        continue

                    app_cat = None
                    if proc in self.app_cat_data:
                        app_cat = self.app_cat_data[proc]
                    malware = is_proc_malware(p_, False)
                    app_cats = {}
                    app_cats['malware'] = malware
                    for c in self.categories:
                        if c == 'malware':
                            app_cats[c] = malware
                        else:
                            app_cats[c] = False
                            if c == app_cat:
                                app_cats[c] = True

#                    if fp_str+proc not in data:
#                        data[fp_str+proc] = []

                    for x_ in p_['dst_info']:
                        dst_x       = x_['dst'].split(')')
                        dst_ip      = dst_x[0][1:]
                        dst_port    = int(dst_x[1][1:])
                        server_name = dst_x[2][1:]
#                        data[fp_str+proc].append((None,None,proc,sha256,'tls',fp_str,dst_ip,dst_port,
#                                                  server_name,x_['count'],None,app_cats))
                        data[key_].append((None,None,proc,sha256,'tls',fp_str,dst_ip,dst_port,
                                           server_name,x_['count'],None,app_cats,self.proc_list))

                        if len(data[key_]) > 5000:
                            key_ += 1
                            data[key_] = []

        print('time to read data:\t%0.2f' % (time.time()-start))

        return data


    def read_file_dmz_json(self, f):
        data = {}

        key_ = 0
        data[key_] = []
        start = time.time()
        for line in os.popen('zcat %s' % (f)):
            fp_ = json.loads(line)
            if 'str_repr' in fp_:
                fp_str = fp_['str_repr']
            else:
                fp_str = fp_['md5']
            if fp_str in schannel_fps:
                fp_str = 'schannel'

            proc = 'dmz_process'
            sha256 = 'dmz_process'
            app_cats = {}
            app_cats['malware'] = False

#            if fp_str not in data:
#                data[fp_str] = []

            for x_ in fp_['dmz_dst_info']:
                dst_x       = x_['dst'].split(')')
                dst_ip      = dst_x[0][1:]
                dst_port    = int(dst_x[1][1:])
                server_name = dst_x[2][1:]
#                data[fp_str].append((None,None,proc,sha256,'tls',fp_str,dst_ip,dst_port,
#                                     server_name,x_['count'],None,app_cats))
                data[key_].append((None,None,proc,sha256,'tls',fp_str,dst_ip,dst_port,
                                   server_name,x_['count'],None,app_cats,None))

                if len(data[key_]) > 5000:
                    key_ += 1
                    data[key_] = []

        print('time to read data:\t%0.2f' % (time.time()-start))

        return data




def get_results(data):
    results = []
    for d_ in data:
        src_ip      = d_[0]
        src_port    = d_[1]
        proc        = d_[2]
        sha256      = d_[3]
        type_       = d_[4]
        str_repr    = d_[5]
        dst_ip      = d_[6]
        dst_port    = d_[7]
        server_name = d_[8]
        cnt         = d_[9]
        os_         = d_[10]
        app_cats    = d_[11]
        target_proc = d_[12]
        protocol    = 6
        ts          = 0.00

#        fp_ = fingerprinter.get_database_entry(str_repr, type_)
#        if fp_ == None:
#            continue

        flow = fingerprinter.process_csv(type_, str_repr, src_ip, dst_ip, src_port, dst_port,
                                         protocol, ts, {'server_name': server_name})
        if 'analysis' not in flow:
            continue
        r_ = flow['analysis']
        if 'probable_processes' not in r_:
            continue
        pi_ = r_['probable_processes'][0]

        app_cat = 'None'
        for k in app_cats:
            if app_cats[k] == True:
                app_cat = k

        o_ = {}
        o_['count'] = cnt
        o_['fp_str'] = str_repr
        o_['score'] = pi_['score']

        o_['ground_truth']   = {'process': proc, 'sha256': sha256, 'server_name': server_name, 'dst_ip': dst_ip}
        o_['ground_truth']['categories'] = {'malware': app_cats['malware'], app_cat: True}
        if target_proc != None:
            for test_proc in target_proc:
                o_['ground_truth']['categories'][test_proc[0]] = False
                if proc in test_proc:
                    o_['ground_truth']['categories'][test_proc[0]] = True

        o_['inferred_truth'] = {'process': pi_['process'], 'sha256': pi_['sha256'], 'probable_processes': r_['probable_processes']}
        o_['inferred_truth']['categories'] = {}
        if target_proc != None:
            for test_proc in target_proc:
                o_['inferred_truth']['categories'][test_proc[0]] = False
                if pi_['process'] in test_proc:
                    o_['inferred_truth']['categories'][test_proc[0]] = True
        o_['inferred_truth']['categories'][pi_['category']] = True
        if 'malware' in pi_:
            o_['inferred_truth']['categories']['malware'] = pi_['malware']
        else:
            o_['inferred_truth']['categories']['malware'] = False

        results.append(o_)

    return tuple(results)


def get_results_blacklist(data):
    global fp_sni_blacklist
    results = []
    for d_ in data:
        src_ip      = d_[0]
        src_port    = d_[1]
        proc        = d_[2]
        sha256      = d_[3]
        type_       = d_[4]
        str_repr    = d_[5]
        dst_ip      = d_[6]
        dst_port    = d_[7]
        server_name = d_[8]
        cnt         = d_[9]
        os_         = d_[10]
        app_cats    = d_[11]
        protocol    = 6
        ts          = 0.00

        o_ = {}
        o_['count'] = cnt
        o_['fp_str'] = str_repr
        o_['score'] = 0.0
        o_['ground_truth']   = {'process': proc, 'sha256': sha256, 'server_name': server_name}
        o_['ground_truth']['categories'] = {'malware': app_cats['malware']}
        o_['inferred_truth'] = {'process': 'n/a', 'sha256': 'n/a'}

#        k = '%s,%s' % (str_repr, server_name)
        k = '%s,%s' % (str_repr, dst_ip)
#        k = '%s' % (dst_ip)
        if k in fp_sni_blacklist:
            o_['inferred_truth']['categories'] = {'malware': True}
        else:
            o_['inferred_truth']['categories'] = {'malware': False}

        results.append(o_)

    return results


def get_results_top(data):
    results = []
    for d_ in data:
        proc        = d_[2]
        sha256      = d_[3]
        type_       = d_[4]
        str_repr    = d_[5]
        dst_ip      = d_[6]
        server_name = d_[8]
        cnt         = d_[9]
        app_cats    = d_[11]
        target_proc = d_[12]

        fp_ = fingerprinter.get_database_entry(str_repr, type_)
        if fp_ == None:
            continue
        if 'process_info' not in fp_:
            continue

        pi_ = fp_['process_info'][0]
        if pi_['process'] == 'Generic DMZ Traffic':
            pi_ = fp_['process_info'][1]
            pi_['malware'] = fp_['process_info'][0]['malware']
        if 'application_category' not in pi_:
            pi_['application_category'] = 'None'

        app_cat = 'None'
        for k in app_cats:
            if app_cats[k] == True:
                app_cat = k

        o_ = {}
        o_['count'] = cnt
        o_['fp_str'] = str_repr
        o_['score'] = 0.0
        o_['ground_truth']   = {'process': proc, 'sha256': sha256, 'server_name': server_name, 'dst_ip': dst_ip}
        o_['ground_truth']['categories'] = {'malware': app_cats['malware'], app_cat: True}
        if target_proc != None:
            for test_proc in target_proc:
                o_['ground_truth']['categories'][test_proc[0]] = False
                if proc in test_proc:
                    o_['ground_truth']['categories'][test_proc[0]] = True

        o_['inferred_truth'] = {'process': pi_['process'], 'sha256': pi_['sha256s']}
        o_['inferred_truth']['categories'] = {}
        if target_proc != None:
            for test_proc in target_proc:
                o_['inferred_truth']['categories'][test_proc[0]] = False
                if pi_['process'] in test_proc:
                    o_['inferred_truth']['categories'][test_proc[0]] = True
        o_['inferred_truth']['categories'][pi_['application_category']] = True
        if 'malware' in pi_:
            o_['inferred_truth']['categories']['malware'] = pi_['malware']
        else:
            o_['inferred_truth']['categories']['malware'] = False
        o_['inferred_truth']['probable_processes'] = []
        for p_ in fp_['process_info'][0:5]:
            o_['inferred_truth']['probable_processes'].append({'process': p_['process']})

        results.append(o_)

    return results


verbose_out = open('verbose_out.txt','w')

def clean_proc(p):
    return p
    p = p.lower().replace('.exe','')
    if p.endswith('d'):
        return p[:-1]
    return p


def process_result(x_):
    global app_families
    global app_families_strict

    sl   = x_[0]
    cats = x_[1]

    results = []

    for r in sl:
        if r == None:
            continue

        count    = r['count']
        tmp_oproc_gt = r['ground_truth']['process']
        oproc_gt = app_families_strict[tmp_oproc_gt] if tmp_oproc_gt in app_families_strict else tmp_oproc_gt
        gproc_gt = clean_proc(app_families[tmp_oproc_gt] if tmp_oproc_gt in app_families else tmp_oproc_gt)
        proc_gt  = clean_proc(oproc_gt)
        sha_gt   = r['ground_truth']['sha256']

        tmp_oproc_nf = r['inferred_truth']['process']
        oproc_nf = app_families_strict[tmp_oproc_nf] if tmp_oproc_nf in app_families_strict else tmp_oproc_nf
        gproc_nf = clean_proc(app_families[tmp_oproc_nf] if tmp_oproc_nf in app_families else tmp_oproc_nf)
        proc_nf  = clean_proc(oproc_nf)
        sha_nf   = r['inferred_truth']['sha256']

        proc_nf2 = None
        gproc_nf2 = None
        if len(r['inferred_truth']['probable_processes']) > 1:
            tmp_oproc_nf2 = r['inferred_truth']['probable_processes'][1]['process']
            oproc_nf2 = app_families_strict[tmp_oproc_nf2] if tmp_oproc_nf2 in app_families_strict else tmp_oproc_nf2
            gproc_nf2 = clean_proc(app_families[tmp_oproc_nf2] if tmp_oproc_nf2 in app_families else tmp_oproc_nf2)
            proc_nf2  = clean_proc(oproc_nf2)

        proc_nf3 = None
        gproc_nf3 = None
        if len(r['inferred_truth']['probable_processes']) > 2:
            tmp_oproc_nf3 = r['inferred_truth']['probable_processes'][2]['process']
            oproc_nf3 = app_families_strict[tmp_oproc_nf3] if tmp_oproc_nf3 in app_families_strict else tmp_oproc_nf3
            gproc_nf3 = clean_proc(app_families[tmp_oproc_nf3] if tmp_oproc_nf3 in app_families else tmp_oproc_nf3)
            proc_nf3  = clean_proc(oproc_nf3)

        proc_nf4 = None
        gproc_nf4 = None
        if len(r['inferred_truth']['probable_processes']) > 3:
            tmp_oproc_nf4 = r['inferred_truth']['probable_processes'][3]['process']
            oproc_nf4 = app_families_strict[tmp_oproc_nf4] if tmp_oproc_nf4 in app_families_strict else tmp_oproc_nf4
            gproc_nf4 = clean_proc(app_families[tmp_oproc_nf4] if tmp_oproc_nf4 in app_families else tmp_oproc_nf4)
            proc_nf4  = clean_proc(oproc_nf4)

        proc_nf5 = None
        gproc_nf5 = None
        if len(r['inferred_truth']['probable_processes']) > 4:
            tmp_oproc_nf5 = r['inferred_truth']['probable_processes'][4]['process']
            oproc_nf5 = app_families_strict[tmp_oproc_nf5] if tmp_oproc_nf5 in app_families_strict else tmp_oproc_nf5
            gproc_nf5 = clean_proc(app_families[tmp_oproc_nf5] if tmp_oproc_nf5 in app_families else tmp_oproc_nf5)
            proc_nf5  = clean_proc(oproc_nf5)

        r_proc   = r['count'] if proc_gt  == proc_nf else 0
        r_gproc  = r['count'] if gproc_gt == gproc_nf else 0
        r_sha    = r['count'] if sha_gt   == sha_nf else 0

        r_proc2 = 0
        if r_proc == 0:
            r_proc2   = r['count'] if proc_gt  == proc_nf2 else 0
        r_gproc2 = 0
        if r_gproc == 0:
            r_gproc2  = r['count'] if gproc_gt == gproc_nf2 else 0

        r_proc3 = 0
        if r_proc == 0 and r_proc2 == 0:
            r_proc3   = r['count'] if proc_gt  == proc_nf3 else 0
        r_gproc3 = 0
        if r_gproc == 0 and r_gproc2 == 0:
            r_gproc3  = r['count'] if gproc_gt == gproc_nf3 else 0

        r_proc4 = 0
        if r_proc == 0 and r_proc2 == 0 and r_proc3 == 0:
            r_proc4   = r['count'] if proc_gt  == proc_nf4 else 0
        r_gproc4 = 0
        if r_gproc == 0 and r_gproc2 == 0 and r_gproc3 == 0:
            r_gproc4  = r['count'] if gproc_gt == gproc_nf4 else 0

        r_proc5 = 0
        if r_proc == 0 and r_proc2 == 0 and r_proc3 == 0 and r_proc4 == 0:
            r_proc5   = r['count'] if proc_gt  == proc_nf5 else 0
        r_gproc5 = 0
        if r_gproc == 0 and r_gproc2 == 0 and r_gproc3 == 0 and r_gproc4 == 0:
            r_gproc5  = r['count'] if gproc_gt == gproc_nf5 else 0

#        if oproc_gt != oproc_nf:
#        if gproc_gt != gproc_nf:
#            verbose_out.write('%i,%s,%s,%s,%s,%f,%s,%s\n' % (count, tmp_oproc_gt.replace(',',''), tmp_oproc_nf, r['ground_truth']['server_name'],
#                                                             r['ground_truth']['dst_ip'], r['score'],sha_gt,r['fp_str']))
#            verbose_out.flush()

        r_cats = []
        for c in cats:
            if c == '':
                continue
            c_gt = False
            c_nf = False
            if c in r['ground_truth']['categories']:
                c_gt = r['ground_truth']['categories'][c]
            if c in r['inferred_truth']['categories']:
                c_nf = r['inferred_truth']['categories'][c]

            r_cat_a  = r['count'] if c_gt   == c_nf                    else 0
            r_cat_tp = r['count'] if c_gt   == True  and c_nf == True  else 0
            r_cat_tn = r['count'] if c_gt   == False and c_nf == False else 0
            r_cat_fp = r['count'] if c_gt   == False and c_nf == True  else 0
            r_cat_fn = r['count'] if c_gt   == True  and c_nf == False else 0

            r_cats.append([r['count'], r_cat_a, r_cat_tp, r_cat_tn, r_cat_fp, r_cat_fn])

#            if c_gt == False and c_nf == True:
            if c_gt == True and c_nf == False:
#            if c_gt == False and c_nf == False:
#                verbose_out.write('%s\n' % (sha_gt))
                verbose_out.write('%i,%s,%s,%s,%s,%f,%s,%s\n' % (count, tmp_oproc_gt.replace(',',''), tmp_oproc_nf, r['ground_truth']['server_name'],
                                                                 r['ground_truth']['dst_ip'], r['score'],sha_gt,r['fp_str']))
                verbose_out.flush()


        results.append((r['count'], r_proc, r_gproc, r_sha, r_proc2, r_gproc2, r_proc3, r_gproc3, r_proc4, r_gproc4, r_proc5, r_gproc5, r_cats))
    return results



def main():
    global fingerprinter
    global verbose_out
    start = time.time()

    parser = optparse.OptionParser()

    parser.add_option('-i','--input',action='store',dest='input',
                      help='daily fingerprint file',default=None)
    parser.add_option('-o','--output',action='store',dest='output',
                      help='output file',default=sys.stdout)
    parser.add_option('-f','--fp_db',action='store',dest='fp_db',
                      help='location of fingerprint database',default='../../../resources/fingerprint_db.json.gz')
    parser.add_option('-c','--categories',action='store',dest='categories',
                      help='test 1-vs-all on specific category, e.g., vpn',default='')
    parser.add_option('-p','--process',action='store',dest='process',
                      help='test on specific processes, e.g., firefox,firefox.exe',default=None)
    parser.add_option('-e','--endpoint',action='store_true',dest='endpoint',
                      help='enable endpoint modeling',default=False)
    parser.add_option('-t','--top',action='store_true',dest='top',
                      help='report most prevalent process',default=False)
    parser.add_option('-b','--blacklist',action='store_true',dest='blacklist',
                      help='use fp/sni blacklist',default=False)
    parser.add_option('-m','--malware_context',action='store',dest='malware_context',
                      help='malware context',default=None)

    options, args = parser.parse_args()

    if options.input == None:
        print('error: need to specify input')

    if options.endpoint and options.input.endswith('.json.gz'):
        print('warning: endpoint modeling not available for json format')
        options.endpoint = False

    if options.blacklist:
        for line in open('data/fp_ip_blacklist.csv','r'):
            fp_sni_blacklist.add(line.strip())


    importlib.machinery.SOURCE_SUFFIXES.append('')
    pmercury = importlib.import_module('..pmercury','pmercury.pmercury')
    fingerprinter = pmercury.Fingerprinter(options.fp_db, 'test.out', True, num_procs=5, human_readable=False,
                                           group=False, experimental=False, endpoint=options.endpoint)

    tester = Validation(options.input, options.fp_db, options.output, options.categories.split(','), options.top, options.blacklist,
                        options.malware_context, options.process)

    tester.validate_process_identification()

    verbose_out.close()

    if options.endpoint:
        fingerprinter.endpoint_model.write_all(fingerprinter.endpoint_file_pointer)


if __name__ == '__main__':
    sys.exit(main())
