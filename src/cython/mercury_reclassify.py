import json
import argparse

from mercury import *


class MercuryReclassify:

    def __init__(self, resources_file):
        self.libmerc = Mercury(do_analysis=True, resources=resources_file.encode())
        self.libmerc.mercury_init()


    def reclassify(self, input_file, output_file):
        out_ = open(output_file, 'w')
        for line in open(input_file):
            try:
                r = json.loads(line)
            except:
                continue
            if 'fingerprints' not in r:
                continue
            if 'tls' in r['fingerprints']:
                str_repr = r['fingerprints']['tls']
                if not str_repr.startswith('tls/'):
                    str_repr = f'tls/{str_repr}'
                dst_ip   = r['dst_ip']
                dst_port = r['dst_port']
                server_name = 'None'
                if 'server_name' in r['tls']['client']:
                    server_name = r['tls']['client']['server_name']
                result = self.libmerc.perform_analysis(str_repr, server_name, dst_ip, dst_port)
                r['new_analysis'] = result['analysis']
                r['new_fingerprint_info'] = result['fingerprint_info']
                out_.write(json.dumps(r) + '\n')
            elif 'http' in r['fingerprints']:
                str_repr = r['fingerprints']['http']
                if not str_repr.startswith('http/'):
                    str_repr = f'http/{str_repr}'
                dst_ip     = r['dst_ip']
                dst_port   = r['dst_port']
                host       = 'None'
                if 'host' in r['http']['request']:
                    host = r['http']['request']['host']
                user_agent = 'None'
                if 'user_agent' in r['http']['request']:
                    user_agent = r['http']['request']['user_agent']
                result = self.libmerc.perform_analysis_with_user_agent(str_repr, host, dst_ip, dst_port, user_agent)
                r['new_analysis'] = result['analysis']
                r['new_fingerprint_info'] = result['fingerprint_info']
                out_.write(json.dumps(r) + '\n')
            elif 'quic' in r['fingerprints']:
                str_repr = r['fingerprints']['quic']
                if not str_repr.startswith('quic/'):
                    str_repr = f'quic/{str_repr}'
                dst_ip   = r['dst_ip']
                dst_port = r['dst_port']
                server_name = 'None'
                if 'server_name' in r['tls']['client']:
                    server_name = r['tls']['client']['server_name']
                user_agent = 'None'
                if 'google_user_agent' in r['tls']['client']:
                    user_agent = r['tls']['client']['google_user_agent']
                result = self.libmerc.perform_analysis_with_user_agent(str_repr, server_name, dst_ip, dst_port, user_agent)
                r['new_analysis'] = result['analysis']
                r['new_fingerprint_info'] = result['fingerprint_info']
                out_.write(json.dumps(r) + '\n')
        out_.close()


    def finalize(self):
        self.libmerc.mercury_finalize()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-i','--input',action='store',dest='merc_file',
                        help='mercury JSON output to reprocess',default=None)
    parser.add_argument('-o','--output',action='store',dest='output_file',
                        help='write reanalyzed mercury data to <output>',default=None)
    parser.add_argument('-r','--resources',action='store',dest='resources',
                        help='location of mercury resources file',default=None)
    args = parser.parse_args()

    if args.merc_file == None:
        print('error: please provide mercury input file')
    if args.output_file == None:
        print('error: please provide output file')
    if args.resources == None:
        print('error: please provide mercury resources file')


    reclassify = MercuryReclassify(args.resources)
    reclassify.reclassify(args.merc_file, args.output_file)
    reclassify.finalize()

if __name__ == "__main__":
    main()





