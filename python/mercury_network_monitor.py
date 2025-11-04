import os
import sys
import json
import time
import fcntl
import socket
import asyncio
import hashlib
import pathlib
import argparse
import binascii
import datetime
import platform
from functools import lru_cache
from threading import Thread

import pcap
import psutil
import mercury


class EndpointInfo:

    def __init__(self):
        self.process_map = {}
        self.os_info = {
            'os': platform.system(),
            'os_edition': platform.release(),
            'os_version': platform.version(),
        }


    def update_process_map(self):
        while True:
            for p in psutil.process_iter(['name', 'ppid', 'exe']):
                if p.pid not in self.process_map or p.info['name'] != self.process_map[p.pid]['process_name']:
                    endpoint_obj = {'process_name': p.info['name'],
                                    'process_hash': self.get_process_hash(p.info['exe']),
                                    'process_path': p.info['exe'],
                                    'ppid':    p.info['ppid']}
                    self.process_map[p.pid] = endpoint_obj


    def update_process_map_pid(self, pid):
        if pid in self.process_map:
            return self.process_map[pid]
        else:
            attempts = 10
            while attempts > 0:
                if psutil.pid_exists(pid):
                    proc = psutil.Process(pid=pid)
                    with proc.oneshot():
                        endpoint_obj = {'process_name': proc.name(),
                                        'process_hash': self.get_process_hash(proc.exe()),
                                        'process_path': proc.exe(),
                                        'ppid':         proc.ppid()}
                        self.process_map[pid] = endpoint_obj
                        return self.process_map[pid]
                attempts -= 1
            return None


    @lru_cache(maxsize=512)
    def get_process_hash(self, process_path):
        if process_path == None or process_path == '':
            return None
        try:
            return hashlib.sha256(open(process_path,'rb').read()).hexdigest()
        except:
            return None


    def get_process_info(self, pid):
        if pid in self.process_map:
            return self.process_map[pid]
        return self.update_process_map_pid(pid)



class NetworkInfo:

    def __init__(self):
        self.network_map = {}


    def update_network_map(self):
        while True:
            for c in psutil.net_connections():
                pid = c[6]
                if pid == None:
                    continue

                if c[2] == socket.SOCK_STREAM:
                    protocol = 6
                elif c[2] == socket.SOCK_DGRAM:
                    protocol = 17
                else:
                    continue

                if len(c[3]) == 0:
                    src_ip   = 'none'
                    src_port = 'none'
                else:
                    src_ip   = c[3][0]
                    src_port = c[3][1]
                if len(c[4]) == 0:
                    dst_ip   = 'none'
                    dst_port = 'none'
                else:
                    dst_ip   = c[4][0]
                    dst_port = c[4][1]

                if src_ip == '0.0.0.0':
                    src_ip = 'none'

                network_tuple = f'{src_ip},{src_port},{dst_ip},{dst_port},{protocol}'
                if network_tuple not in self.network_map:
                    net_obj = {'pid':      pid,
                               'src_ip':   src_ip,
                               'src_port': src_port,
                               'dst_ip':   dst_ip,
                               'dst_port': dst_port,
                               'protocol': protocol}
                    self.network_map[network_tuple] = net_obj


    def get_connection_info(self, flow_key):
        if flow_key in self.network_map:
            return self.network_map[flow_key]
        return None


    def print_network_map(self):
        print('print_network_map()')
        for k,v in self.network_map.items():
            print(f'{k}:-:{v}')



class Monitor:

    def __init__(self, network_interface, out_folder, rotate_num):
        self.rand_id = binascii.b2a_hex(os.urandom(15)).decode()[0:8]
        self.network_interface = network_interface
        self.out_folder = out_folder
        if not os.path.isdir(self.out_folder):
            os.makedirs(self.out_folder)
        self.written_records = 0
        self.file_no = -1
        self.rotate_num = rotate_num
        self.cur_datetime = datetime.datetime.today().strftime('%Y-%m-%d')
        self.out_file = None
        self.rotate_output_file()

        self.endpoint_info = EndpointInfo()
        self.network_info  = NetworkInfo()

        self.net_info_thread = Thread(target=self.network_info.update_network_map, daemon=True)
        self.net_info_thread.start()

        self.endpoint_info_thread = Thread(target=self.endpoint_info.update_process_map, daemon=True)
        self.endpoint_info_thread.start()

        self.libmerc = mercury.Mercury(metadata_output=True, dns_json_output=True,
                                       certs_json_output=True)
        self.libmerc.mercury_init()


    def rotate_output_file(self):
        if self.cur_datetime != datetime.datetime.today().strftime('%Y-%m-%d'):
            self.cur_datetime = datetime.datetime.today().strftime('%Y-%m-%d')
            self.file_no = -1
        if self.out_file != None:
            self.out_file.close()
        self.file_no += 1
        self.out_file = open(f'{self.out_folder}/network-monitor-{self.cur_datetime}-{self.rand_id}-{self.file_no}.json','a')


    def write_output(self, record):
        self.out_file.write(f'{json.dumps(record)}\n')
        self.written_records += 1
        if self.written_records >= self.rotate_num:
            self.written_records = 0
            self.rotate_output_file()


    def execute(self):
        import signal
        def signal_handler(signal, frame):
            if self.out_file != None:
                self.out_file.close()
            sys.exit(0)
        signal.signal(signal.SIGINT, signal_handler)

        p = pcap.pcap(self.network_interface, promisc=True, immediate=True, timeout_ms=50)

        while True:
            p.dispatch(1, self.process_packet)


    def process_packet(self, ts, buf):
        r = self.libmerc.get_mercury_json(buf)

        if r != None:
            r['event_start'] = time.time()
            flow_key   = f"{r['src_ip']},{r['src_port']},{r['dst_ip']},{r['dst_port']},{r['protocol']}"
            flow_key_r = f"{r['dst_ip']},{r['dst_port']},{r['src_ip']},{r['src_port']},{r['protocol']}"

            conn_info = self.network_info.get_connection_info(flow_key)
            if conn_info == None:
                conn_info = self.network_info.get_connection_info(flow_key_r)
            if conn_info == None:
                min_flow_key = f"none,{r['src_port']},none,none,{r['protocol']}"
                conn_info = self.network_info.get_connection_info(min_flow_key)

            if conn_info == None:
                time.sleep(0.1)
                conn_info = self.network_info.get_connection_info(flow_key)
                if conn_info == None:
                    conn_info = self.network_info.get_connection_info(flow_key_r)

            ground_truth = {}
            if conn_info != None:
                proc_info = self.endpoint_info.get_process_info(conn_info['pid'])
                if proc_info == None:
                    time.sleep(0.1)
                    proc_info = self.endpoint_info.get_process_info(conn_info['pid'])

                if proc_info != None:
                    ground_truth['process_name'] = proc_info['process_name']
                    ground_truth['process_hash'] = proc_info['process_hash']
                    ground_truth['process_path'] = proc_info['process_path']

                    # get parent info
                    parent_info = self.endpoint_info.get_process_info(proc_info['ppid'])
                    if parent_info != None:
                        ground_truth['parent_name'] = parent_info['process_name']
                        ground_truth['parent_hash'] = parent_info['process_hash']
                        ground_truth['parent_path'] = parent_info['process_path']
                else:
                    ground_truth['process_pid']  = conn_info['pid']
            os_info = self.endpoint_info.os_info
            ground_truth['os']         = os_info['os']
            ground_truth['os_version'] = os_info['os_version']
            ground_truth['os_edition'] = os_info['os_edition']
            r['ground_truth']          = ground_truth
            self.write_output(r)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-m','--mode',action='store',dest='mode',
                        help='operation mode: endpoint',default='endpoint')
    parser.add_argument('-i','--interface',action='store',dest='network_interface',
                        help='network interface to monitor',default='enp0s3')
    parser.add_argument('-o','--output-folder',action='store',dest='out_folder',
                        help='full path to folder to write output',default='nm-output')
    parser.add_argument('-l','--limit',action='store',dest='limit',
                        help='rotate output file after <limit>',default='1000')
    args = parser.parse_args()

    monitorer = Monitor(args.network_interface, args.out_folder, int(args.limit))
    monitorer.execute()


if __name__ == "__main__":
    main()
