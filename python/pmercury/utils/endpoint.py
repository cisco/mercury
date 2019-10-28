import ujson as json
from copy import deepcopy

class Endpoint:

    def __init__(self):
        self.ip_to_mac = {}
        self.endpoints = {}


    def update(self, flow):
        src = flow['src_ip']
        fp_type = list(flow['fingerprints'].keys())[0]
        fp_ = flow['fingerprints'][fp_type]

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
            if src not in self.endpoints:
                self.endpoints[src] = {}
        elif src not in self.endpoints:
            self.endpoints[src] = {}

        if fp_type not in self.endpoints[src]:
            self.endpoints[src][fp_type] = {}

        if fp_ not in self.endpoints[src][fp_type]:
            self.endpoints[src][fp_type][fp_] = {}
            self.endpoints[src][fp_type][fp_]['count'] = 0

        self.endpoints[src][fp_type][fp_]['count'] += 1
        if fp_type in flow:
            if 'context' not in self.endpoints[src][fp_type][fp_]:
                self.endpoints[src][fp_type][fp_]['context'] = {}
            for k_ in flow[fp_type]:
                if k_ not in self.endpoints[src][fp_type][fp_]['context']:
                    self.endpoints[src][fp_type][fp_]['context'][k_] = {}
                if flow[fp_type][k_] not in self.endpoints[src][fp_type][fp_]['context'][k_]:
                    self.endpoints[src][fp_type][fp_]['context'][k_][flow[fp_type][k_]] = 0
                self.endpoints[src][fp_type][fp_]['context'][k_][flow[fp_type][k_]] += 1


    def write_all(self, out):
        for id_ in self.endpoints:
            o_ = {}
            o_['identifier'] = id_
            o_['fingerprints'] = self.endpoints[id_]

            out.write(json.dumps(o_) + '\n')


