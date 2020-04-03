import os
import sys
import gzip
import copy
import json
import pyasn
import operator
from collections import OrderedDict, defaultdict


sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from pmercury.utils.pmercury_utils import *


tlds = set([])
if os.name == 'nt':
    import gzip
    public_suffix_file_raw = find_resource_path('resources/public_suffix_list.dat.gz')
    for line in gzip.open(public_suffix_file_raw, 'r'):
        line = line.strip()
        if line.startswith(b'//') or line == b'':
            continue
        if line.startswith(b'*'):
            line = line[2:]
        tlds.add(line.decode())
else:
    public_suffix_file_raw = find_resource_path('resources/public_suffix_list.dat.gz')
    for line in os.popen('zcat %s' % (public_suffix_file_raw)):
        line = line.strip()
        if line.startswith('//') or line == '':
            continue
        if line.startswith('*'):
            line = line[2:]
        tlds.add(line)




class EquivalenceClasses:

    def __init__(self, resource_dir):
        self.classes = defaultdict(list)
#        self.dst_keys = ['classes_hostname_domains','classes_hostname_tlds']
#        self.dst_keys = ['classes_hostname_domains']
        self.dst_features = set(['dst_ip','dst_port','server_name'])
        self.dict_data = {}
        self.radix_tries = {}
        self.load_files(resource_dir)


    def load_files(self, idir):
        files = os.listdir(idir)
        for f in files:
            if not f.endswith('.gz'):
                continue
            with gzip.open(idir + f) as in_file:
                t_ = json.loads(in_file.readline())
                if t_['type'] == 'identity':
                    t_['mapper'] = (lambda v_, _: v_)
                elif t_['type'] == 'dict':
                    self.dict_data[t_['name']] = t_['data']
                    t_['mapper'] = (lambda v_, f_: str(self.dict_data[f_][v_]) if v_ in self.dict_data[f_] else 'unknown')
                elif t_['type'] == 'dict_identity':
                    self.dict_data[t_['name']] = t_['data']
                    t_['mapper'] = (lambda v_, f_: str(self.dict_data[f_][v_]) if v_ in self.dict_data[f_] else v_)
                elif t_['type'] == 'radix':
                    self.prepare_radix(t_)
                    t_['mapper'] = (lambda v_, f_: str(self.radix_tries[f_].search_best(v_).asn)
                                    if self.radix_tries[f_].search_best(v_) != None else 'unknown')
                else:
                    continue

                self.classes[t_['feature']].append(t_)
#                if t_['feature'] in self.dst_features:
#                    self.dst_keys.append(t_['name'])


    def get_str_repr(self, str_repr):
        try:
            return self.classes['str_repr'][0]['mapper'](str_repr, 'classes_str_repr_libraries')
        except:
            return str_repr


    def get_dst_info(self, dst_ip, dst_port, server_name):
        features = []
        domain_, tld_ = self.clean_hostname(server_name)
        features.extend([('classes_hostname_domains',domain_),('classes_hostname_tlds',tld_)])
#        features.extend([('classes_hostname_domains',domain_)])

        for feature in self.dst_features:
            if feature == 'dst_ip':
                cur_f = dst_ip
            elif feature == 'dst_port':
                cur_f = dst_port
            elif feature == 'server_name':
                cur_f = server_name
            else:
                continue

            for x_ in self.classes[feature]:
                features.append((x_['name'], x_['mapper'](str(cur_f), x_['name'])))

        return features


    def prepare_radix(self, t_):
        rtrie = pyasn.pyasn_radix.Radix()
        e_str = []
        for k,v in t_['data'].items():
            e_str.append('%s\t%s\n' % (k, v))
        rtrie.load_ipasndb("", ''.join(e_str))

        self.radix_tries[t_['name']] = rtrie


    def clean_hostname(self, hostname):
        if hostname == None or hostname == 'None':
            return 'None', 'None'
        tokens_ = hostname.split('.')
        tld_ = tokens_[-1]
        tmp_tld_ = tokens_[-1]
        domain_ = tokens_[-1]
        tmp_domain_ = tokens_[-1]
        if len(tokens_) > 1:
            domain_ = tokens_[-2] + '.' + domain_
            tmp_domain_ = tokens_[-2] + '.' + tmp_domain_
        for i in range(2,7):
            if len(tokens_) < i:
                return domain_, tld_
            if len(tokens_) > i:
                tmp_domain_ = tokens_[(i+1)*-1] + '.' + tmp_domain_
            tmp_tld_ = tokens_[i*-1] + '.' + tmp_tld_
            if tmp_tld_ in tlds:
                domain_ = tmp_domain_
                tld_ = tmp_tld_

        return domain_, tld_
