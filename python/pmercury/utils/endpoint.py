import ujson as json
from copy import deepcopy

class Endpoint:

    def __init__(self):
        self.ip_to_mac = {}
        self.endpoints = {}


    def update(self, flow):
        fp_type = next(iter(flow['fingerprints']))
        fp_     = flow['fingerprints'][fp_type]
        src     = self.get_src(flow, fp_type)

        if src not in self.endpoints:
            self.endpoints[src] = {}
            self.endpoints[src]['summary'] = {}
            self.endpoints[src]['prev_flow'] = None
        if fp_type not in self.endpoints[src]:
            self.endpoints[src]['summary'][fp_type] = {}

        self.endpoints[src]['prev_flow'] = flow

        if fp_ not in self.endpoints[src]['summary'][fp_type]:
            self.endpoints[src]['summary'][fp_type][fp_] = {}
            self.endpoints[src]['summary'][fp_type][fp_]['count'] = 0

        self.endpoints[src]['summary'][fp_type][fp_]['count'] += 1
        if fp_type in flow:
            if 'context' not in self.endpoints[src]['summary'][fp_type][fp_]:
                self.endpoints[src]['summary'][fp_type][fp_]['context'] = {}
            for k_ in flow[fp_type]:
                if k_ not in self.endpoints[src]['summary'][fp_type][fp_]['context']:
                    self.endpoints[src]['summary'][fp_type][fp_]['context'][k_] = {}
                if flow[fp_type][k_] not in self.endpoints[src]['summary'][fp_type][fp_]['context'][k_]:
                    self.endpoints[src]['summary'][fp_type][fp_]['context'][k_][flow[fp_type][k_]] = 0
                self.endpoints[src]['summary'][fp_type][fp_]['context'][k_][flow[fp_type][k_]] += 1


    def write_all(self, out):
        for id_ in self.endpoints:
            o_ = {}
            o_['identifier'] = id_
            o_['fingerprints'] = self.endpoints[id_]

            out.write(json.dumps(o_) + '\n')


    def get_prev_flow(self, src):
        try:
            return self.endpoints[src]['prev_flow']
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


