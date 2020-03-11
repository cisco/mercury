"""
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import os
import sys
import json
import gzip
from copy import deepcopy
from collections import defaultdict, OrderedDict

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from pmercury.utils.pmercury_utils import *


strong_domains_file = find_resource_path('resources/domain_indicators.json.gz')
with gzip.open(strong_domains_file) as in_:
    strong_domains = json.loads(in_.readline())


class Endpoint:

    def __init__(self):
        self.summary    = {}
        self.os_info    = defaultdict(float)
        self.prot_count = defaultdict(int)
        self.prev_flow  = None
        self.strong_procs = set([])

    def update(self, flow, fp_type, fp_):
        self.prev_flow = flow
        self.prot_count[fp_type] += 1

        if fp_type not in self.summary:
            self.summary[fp_type] = {}

        if fp_ not in self.summary[fp_type]:
            self.summary[fp_type][fp_] = {}
            self.summary[fp_type][fp_]['count'] = 0
        self.summary[fp_type][fp_]['count'] += 1

        if fp_type in flow:
            if 'context' not in self.summary[fp_type][fp_]:
                self.summary[fp_type][fp_]['context'] = defaultdict(lambda: defaultdict(int))
            for k_ in flow[fp_type]:
                self.summary[fp_type][fp_]['context'][k_][flow[fp_type][k_]] += 1

        if 'analysis' in flow and 'os_info' in flow['analysis'] and 'probable_oses' in flow['analysis']['os_info']:
            for x_ in flow['analysis']['os_info']['probable_oses']:
                self.os_info[x_['os']] += x_['score']

        if fp_type == 'tls' and fp_type in flow and 'server_name' in flow[fp_type]:
            server_name = flow[fp_type]['server_name']
            if server_name in strong_domains:
                self.strong_procs.add(strong_domains[server_name])

    def get_os(self):
        tmp_os = []
        for k in self.os_info:
            tmp_os.append((self.os_info[k]/self.prot_count['tcp'], k))
        tmp_os.sort(reverse=True)
        os_info = OrderedDict({})
        for c,k in tmp_os:
            os_info[k] = c
        return os_info



class Endpoints:

    def __init__(self):
        self.ip_to_mac = {}
        self.endpoints = {}


    def update(self, flow):
        if 'fingerprints' not in flow:
            return

        fp_type = next(iter(flow['fingerprints']))
        fp_     = flow['fingerprints'][fp_type]
        src     = self.get_src(flow, fp_type)

        if src not in self.endpoints:
            self.endpoints[src] = Endpoint()

        self.endpoints[src].update(flow, fp_type, fp_)


    def write_all(self, out):
        for id_ in self.endpoints:
            o_ = {}
            o_['identifier'] = id_
            o_['fingerprints'] = self.endpoints[id_].summary
            o_['os_info']      = self.endpoints[id_].get_os()

            out.write(json.dumps(o_) + '\n')


    def get_endpoint(self, src):
        try:
            return self.endpoints[src]
        except KeyError:
            return None


    def get_prev_flow(self, src):
        try:
            return self.endpoints[src].prev_flow
        except KeyError:
            return None


    def get_src(self, flow, fp_type):
        src = flow['src_ip']
        if fp_type == 'dhcp':
            if fp_type in flow and 'client_mac_address' in flow[fp_type] and 'requested_ip' in flow[fp_type]:
                mac = flow[fp_type]['client_mac_address']
                src = flow[fp_type]['requested_ip']
                self.ip_to_mac[flow[fp_type]['requested_ip']] = mac

        if src in self.ip_to_mac:
            src_mac = self.ip_to_mac[src]
            if src in self.endpoints:
                self.endpoints[src_mac] = deepcopy(self.endpoints[src])
                del self.endpoints[src]
            src = src_mac

        return src


