import json
from copy import deepcopy
from collections import defaultdict

class Endpoint:

    def __init__(self):
        self.summary = {}
        self.prev_flow = None

    def update(self, flow, fp_type, fp_):
        self.prev_flow = flow

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


class Endpoints:

    def __init__(self):
        self.ip_to_mac = {}
        self.endpoints = {}


    def update(self, flow):
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


