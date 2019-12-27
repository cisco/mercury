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


class Validation:

    def __init__(self, in_file, fp_db_name, output, categories, top):
        if output == sys.stdout:
            self.out_file_pointer = sys.stdout
        else:
            self.out_file_pointer = open(output, 'w')
        self.categories = categories
        self.top = top

        self.uninformative_proc_names = set(['vmnet-natd','vmnat','vmnet-natd.exe','vmnat.exe',
                                             'svchost.exe','Unknown','VirtualBoxVM.exe','VirtualBoxVM',
                                             'VirtualBox','VirtualBox.exe','VBoxHeadless','VBoxHeadless.exe',
                                             'VBoxNetNAT.exe','NoxVMHandle.exe','prl_naptd','qemu-system-i386.exe',
                                             'VMware Fusion','vmrc.exe','vmplayer.exe','vmware.exe','vmware-view.exe',
                                             'vmware-remotemks.exe','vmware-view','vmware-vmrc.exe','VMware Remote Console',
                                             'com.docker.vpnkit','vpnkit.exe','vpnkit','vpnui.exe','wepsvc.exe','WerFault.exe',
                                             'SearchProtocolHost.exe','backgroundTaskHost.exe','WWAHost.exe','dsb.exe','node.exe',
                                             'webfilterproxyd','SophosWebIntelligence','swi_fc.exe','DgWip.exe','dgwipd',
                                             'FreedomProxy'])


        # read in application categories
        app_cat_file = 'application_categories.json.gz'
        with gzip.open(app_cat_file,'r') as fp:
            self.app_cat_data = json.loads(fp.read())

        self.input_file = in_file
        if in_file.endswith('.csv.gz'):
            self.data = self.read_file_csv(in_file)
        elif in_file.endswith('.json.gz'):
            self.data = self.read_file_json(in_file)
        else:
            print('error: file format not supported')
            sys.exit(-1)

        self.mt_pool = Pool(8)


    def validate_process_identification(self):
        results = []
        unknown_fp = 0
        unknown_s  = 0

        if self.top:
            results = self.mt_pool.map(get_results_top, [self.data[k] for k in self.data])
        else:
            results = self.mt_pool.map(get_results, [self.data[k] for k in self.data])

        self.analyze_results(results)


    def analyze_results(self, results):
        r_tmp_ = self.mt_pool.map(process_result, [(sl, self.categories) for sl in results])
        r_tmp_ = [x for sl in r_tmp_ for x in sl]
        r_ = [sum([row[i] for row in r_tmp_]) for i in range(0,len(r_tmp_[0][:-1]))]

        print('FILE: %s' % self.input_file)
        print('\tTotal:\t\t\t\t    % 8i' % r_[0])
        print('\tProcess Name Category Accuracy:\t    %0.6f' % (r_[2]/r_[0]))
        print('\tProcess Name Accuracy:\t\t    %0.6f' % (r_[1]/r_[0]))
        print('\tSHA-256 Accuracy:\t\t    %0.6f' % (r_[3]/r_[0]))

        r_c = [row[-1] for row in r_tmp_]
        idx = 0
        for c in self.categories:
            if c == '':
                continue
            r_ = [sum([row[idx][i] for row in r_c]) for i in range(0,len(r_c[0][0]))]
            print('\n\t%s Accuracy:\t\t    %0.6f' % (c, (r_[1]/r_[0])))
            print('\t%s Confusion Matrix:' % c)
            print('\t\t\t   Postive       Negative')
            print('\t\tPositive:% 9i\t% 9i' % (r_[2], r_[5]))
            print('\t\tNegative:% 9i\t% 9i' % (r_[4], r_[3]))

            idx += 1


    def read_file_csv(self, f):
        data = {}

        start = time.time()
        for line in os.popen('zcat %s' % (f)):
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
            dst_ip      = dst_x[0][1:]
            dst_port    = int(dst_x[1][1:])
            server_name = dst_x[2][1:]
            src_port    = int(t_[9].split(')')[1][1:])

            app_cat = None
            if proc in self.app_cat_data:
                app_cat = self.app_cat_data[proc]
            malware = is_proc_malware({'process':proc}, False)
            app_cats = {}
            app_cats['malware'] = malware
            for c in self.categories:
                if c == 'malware':
                    app_cats[c] = malware
                else:
                    app_cats[c] = False
                    if c == app_cat:
                        app_cats[c] = True

            if os_ == None or proc in self.uninformative_proc_names:
                continue

            if src not in data:
                data[src] = []

            data[src].append((src,src_port,proc,sha256,type_,fp_str,dst_ip,dst_port,server_name,1,os_,app_cats))

        print('time to read data:\t%0.2f' % (time.time()-start))

        return data


    def read_file_json(self, f):
        data = {}

        start = time.time()
        for line in os.popen('zcat %s' % (f)):
            fp_ = json.loads(line)
            fp_str = fp_['md5']

            if 'process_info' in fp_:
                new_procs = []
                for p_ in fp_['process_info']:
                    if 'process' not in p_:
                        p_['process'] = p_['filename']
                    if 'av_sigs' in p_ or 'parent_av_sigs' in p_:
                        new_procs.extend(clean_malware_proc(p_))
                    else:
                        new_procs.append(p_)
                fp_['process_info'] = new_procs


                fp_malware_ = is_fp_malware(fp_)
                for p_ in fp_['process_info']:
                    proc = p_['process']
                    sha256 = p_['sha256']

                    if p_['process'] in self.uninformative_proc_names:
                        continue

                    app_cat = None
                    if proc in self.app_cat_data:
                        app_cat = self.app_cat_data[proc]
                    malware = is_proc_malware(p_, fp_malware_)
                    app_cats = {}
                    app_cats['malware'] = malware
                    for c in self.categories:
                        if c == 'malware':
                            app_cats[c] = malware
                        else:
                            app_cats[c] = False
                            if c == app_cat:
                                app_cats[c] = True

                    if fp_str+proc not in data:
                        data[fp_str+proc] = []

                    for x_ in p_['dst_info']:
                        dst_x       = x_['dst'].split(')')
                        dst_ip      = dst_x[0][1:]
                        dst_port    = int(dst_x[1][1:])
                        server_name = dst_x[2][1:]
                        data[fp_str+proc].append((None,None,proc,sha256,'tls',fp_str,dst_ip,dst_port,
                                                  server_name,x_['count'],None,app_cats))
 
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
        protocol    = 6
        ts          = 0.00

        flow = fingerprinter.process_csv('tls', str_repr, src_ip, dst_ip, src_port, dst_port,
                                         protocol, ts, {'server_name': server_name})
        if 'analysis' not in flow:
            continue
        r_ = flow['analysis']
        pi_ = r_['probable_processes'][0]

        app_cat = 'None'
        for k in app_cats:
            if app_cats[k] == True:
                app_cat = k

        o_ = {}
        o_['count'] = cnt
        o_['fp_str'] = str_repr
        o_['score'] = pi_['score']
        o_['ground_truth']   = {'process': proc, 'sha256': sha256, 'server_name': server_name}
        o_['ground_truth']['categories'] = {'malware': app_cats['malware'], app_cat: True}
        o_['inferred_truth'] = {'process': pi_['process'], 'sha256': pi_['sha256']}
        o_['inferred_truth']['categories'] = {'malware': pi_['malware'], pi_['category']: True}

        results.append(o_)

    return results


def get_results_top(data):
    results = []
    for d_ in data:
        proc        = d_[2]
        sha256      = d_[3]
        type_       = d_[4]
        str_repr    = d_[5]
        server_name = d_[8]
        cnt         = d_[9]
        app_cats    = d_[11]

        fp_ = fingerprinter.get_database_entry(str_repr, type_)
        if fp_ == None:
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
        o_['ground_truth']   = {'process': proc, 'sha256': sha256, 'server_name': server_name}
        o_['ground_truth']['categories'] = {'malware': app_cats['malware'], app_cat: True}
        o_['inferred_truth'] = {'process': pi_['process'], 'sha256': pi_['sha256s']}
        o_['inferred_truth']['categories'] = {'malware': pi_['malware'], pi_['application_category']: True}


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

    sl   = x_[0]
    cats = x_[1]

    results = []

    for r in sl:
        if r == None:
            continue

        count    = r['count']
        oproc_gt = r['ground_truth']['process']
        gproc_gt = clean_proc(app_families[oproc_gt] if oproc_gt in app_families else oproc_gt)
        proc_gt  = clean_proc(oproc_gt)
        sha_gt   = r['ground_truth']['sha256']
        oproc_nf = r['inferred_truth']['process']
        gproc_nf = clean_proc(app_families[oproc_nf] if oproc_nf in app_families else oproc_nf)
        proc_nf  = clean_proc(oproc_nf)
        sha_nf   = r['inferred_truth']['sha256']

        r_proc   = r['count'] if proc_gt  == proc_nf else 0
        r_gproc  = r['count'] if gproc_gt == gproc_nf else 0
        r_sha    = r['count'] if sha_gt   == sha_nf else 0

#        if gproc_gt != gproc_nf:
#            verbose_out.write('%i,%s,%s,%s,%f,%s\n' % (count, oproc_gt, oproc_nf, r['ground_truth']['server_name'],
#                                                       r['score'],r['fp_str']))
#            verbose_out.flush()

        r_cats = []
        for c in cats:
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

            if c_gt   == False and c_nf == True:
                verbose_out.write('%i,%s,%s,%s,%f,%s\n' % (count, oproc_gt, oproc_nf, r['ground_truth']['server_name'],
                                                           r['score'],r['fp_str']))
                verbose_out.flush()


        results.append([r['count'], r_proc, r_gproc, r_sha, r_cats])
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
    parser.add_option('-e','--endpoint',action='store_true',dest='endpoint',
                      help='enable endpoint modeling',default=False)
    parser.add_option('-t','--top',action='store_true',dest='top',
                      help='report most prevalent process',default=False)

    options, args = parser.parse_args()

    if options.input == None:
        print('error: need to specify input')

    if options.endpoint and options.input.endswith('.json.gz'):
        print('warning: endpoint modeling not available for json format')
        options.endpoint = False

    importlib.machinery.SOURCE_SUFFIXES.append('')
    pmercury = importlib.import_module('..pmercury','pmercury.pmercury')
    fingerprinter = pmercury.Fingerprinter(options.fp_db, 'test.out', True, num_procs=5, human_readable=False,
                                           group=False, experimental=False, endpoint=options.endpoint)

    tester = Validation(options.input, options.fp_db, options.output, options.categories.split(','), options.top)

    tester.validate_process_identification()

    verbose_out.close()


if __name__ == '__main__':
    sys.exit(main())
