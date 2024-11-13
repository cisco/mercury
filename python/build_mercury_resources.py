import os
import json
import argparse
import datetime
import subprocess
from collections import defaultdict


class MercResourcesBuilder:

    def __init__(self, data_dir, resources_dir):
        self.SUPPORTED_PROTOCOLS = set(['tls','http','quic'])

        self.fp_database   = {}
        self.resources_dir = resources_dir

        # gen database
        fpdb, tls_prevalence = self.gen_database(data_dir)

        # write out fingerprint_db
        with open(f'{self.resources_dir}/fingerprint_db.json','w') as out_:
            for fp in fpdb:
                out_.write(f'{json.dumps(fp)}\n')
        # create version file
        with open(f'{self.resources_dir}/VERSION','w') as out_:
            out_.write(f'{datetime.datetime.now():%Y.%m.%d}; 2.0.dual\n')
        # create DoH watchlist file
        with open(f'{self.resources_dir}/doh-watchlist.txt','w') as out_:
            out_.write(f'1.1.1.1\n')
            out_.write(f'1.0.0.1\n')
            out_.write(f'8.8.8.8\n')
            out_.write(f'8.8.4.4\n')
        # create fp prevalence file
        with open(f'{self.resources_dir}/fp_prevalence_tls.txt','w') as out_:
            for v,k in sorted([(v,k) for k,v in tls_prevalence.items()], reverse=True)[:1000]:
                out_.write(f'{k}\n')
        subprocess.run(['tar', 'cvzf', f'{self.resources_dir}/resources-mp.tgz', f'-C', self.resources_dir,
                        'fingerprint_db.json', 'VERSION', 'doh-watchlist.txt', 'fp_prevalence_tls.txt'])

    # TODO: use python psl package?
    def get_domain_name(self, hostname):
        if hostname == None or hostname == 'None':
            return 'None'

        components = hostname.split('.')
        if len(components) <= 2:
            return hostname

        return f'{components[-2]}.{components[-1]}'


    def extract_data_features(self, merc_record):

        # check if fingerprint is available and a supported type
        if 'fingerprints' not in merc_record:
            return None, None, None, None, None, None, None, None
        fp_type = next(iter(merc_record['fingerprints']))
        if fp_type not in self.SUPPORTED_PROTOCOLS:
            return None, None, None, None, None, None, None, None

        # check if we got process information
        if 'process' not in merc_record or 'process' not in merc_record['process']:
            return None, None, None, None, None, None, None, None

        label    = merc_record['process']['process']
        sha256   = merc_record['process']['sha256']
        fp_str   = merc_record['fingerprints'][fp_type]
        dst_ip   = merc_record['dst_ip']
        dst_port = merc_record['dst_port']
        if fp_type in ['tls','quic']:
            try:
                hostname = merc_record['tls']['client']['server_name']
            except:
                hostname = 'None'
        elif fp_type == 'http':
            try:
                hostname = merc_record['http']['request']['host']
            except:
                hostname = 'None'
        else:
            hostname = 'None'
        if fp_type == 'http':
            try:
                user_agent = merc_record['http']['request']['user_agent']
            except:
                user_agent = 'None'
        else:
            user_agent = None

        return fp_type, label, sha256, fp_str, dst_ip, dst_port, hostname, user_agent

    def gen_database(self, data_dir):
        fpdb = {}
        tls_prevalence = defaultdict(int)
        for filename in os.listdir(data_dir):

            for line in open(f'{data_dir}/{filename}'):
                try:
                    merc_record = json.loads(line)
                except:
                    continue

                fp_type, label, sha256, fp_str, dst_ip, dst_port, hostname, user_agent = self.extract_data_features(merc_record)
                if label == None:
                    continue
                if fp_type == 'tls':
                    tls_prevalence[fp_str] += 1

                if fp_str not in fpdb:
                    fpdb[fp_str] = {}
                    fpdb[fp_str]['total_count']  = 0
                    fpdb[fp_str]['fp_type']      = fp_type
                    fpdb[fp_str]['process_info'] = {}
                if label not in fpdb[fp_str]['process_info']:
                    fpdb[fp_str]['process_info'][label] = {}
                    fpdb[fp_str]['process_info'][label]['count']                    = 0
                    fpdb[fp_str]['process_info'][label]['sha256']                   = sha256
                    fpdb[fp_str]['process_info'][label]['classes_port_port']        = defaultdict(int)
                    fpdb[fp_str]['process_info'][label]['classes_ip_ip']            = defaultdict(int)
#                    fpdb[fp_str]['process_info'][label]['classes_ip_as']            = defaultdict(int)
                    fpdb[fp_str]['process_info'][label]['classes_user_agent']       = defaultdict(int)
                    fpdb[fp_str]['process_info'][label]['classes_hostname_sni']     = defaultdict(int)
                    fpdb[fp_str]['process_info'][label]['classes_hostname_domains'] = defaultdict(int)

                fpdb[fp_str]['total_count'] += 1
                fpdb[fp_str]['process_info'][label]['count'] += 1
                fpdb[fp_str]['process_info'][label]['classes_port_port'][str(dst_port)] += 1
                fpdb[fp_str]['process_info'][label]['classes_ip_ip'][dst_ip] += 1
#                fpdb[fp_str]['process_info'][label]['classes_ip_as'][self.ip_to_as(dst_ip)] += 1
                if hostname != None:
                    fpdb[fp_str]['process_info'][label]['classes_hostname_sni'][hostname] += 1
                    fpdb[fp_str]['process_info'][label]['classes_hostname_domains'][self.get_domain_name(hostname)] += 1
                if user_agent != None:
                    fpdb[fp_str]['process_info'][label]['classes_user_agent'][user_agent] += 1

            fpdb_out = []
            for fp_str, fp_data in fpdb.items():
                new_fp = {}
                new_fp['str_repr']     = fp_str
                new_fp['total_count']  = fp_data['total_count']
                new_fp['fp_type']      = fp_data['fp_type']
                new_fp['process_info'] = []
                for process, process_data in fp_data['process_info'].items():
                    new_process = {}
                    new_process['process'] = process
                    new_process['count']   = process_data['count']
                    new_process['sha256']  = process_data['sha256']
                    new_process['malware'] = False
                    new_process['classes_port_port'] = {}
                    for k,v in process_data['classes_port_port'].items():
                        new_process['classes_port_port'][k] = v
                    new_process['classes_ip_ip'] = {}
                    for k,v in process_data['classes_ip_ip'].items():
                        new_process['classes_ip_ip'][k] = v
                    new_process['classes_user_agent'] = {}
                    for k,v in process_data['classes_user_agent'].items():
                        new_process['classes_user_agent'][k] = v
#                    new_process['classes_ip_as'] = {}
#                    for k,v in process_data['classes_ip_as'].items():
#                        new_process['classes_ip_as'][k] = v
                    new_process['classes_hostname_sni'] = {}
                    for k,v in process_data['classes_hostname_sni'].items():
                        new_process['classes_hostname_sni'][k] = v
                    new_process['classes_hostname_domains'] = {}
                    for k,v in process_data['classes_hostname_domains'].items():
                        new_process['classes_hostname_domains'][k] = v

                    new_fp['process_info'].append(new_process)
                fpdb_out.append(new_fp)

        return fpdb_out, tls_prevalence



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d','--data-dir',action='store',dest='data_dir',
                        help='path to location of mercury_network_monitor.py output',default='data')
    parser.add_argument('-r','--resources-dir',action='store',dest='resources_dir',
                        help='path to write out resources file',default='resources')
    args = parser.parse_args()

    mrb = MercResourcesBuilder(args.data_dir, args.resources_dir)


if __name__ == "__main__":
    main()



