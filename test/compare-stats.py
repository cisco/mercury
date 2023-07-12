import sys
import json
import argparse
import os
from pathlib import Path
import gzip
from collections import defaultdict


def update_stats_db(stats, src_ip, str_repr, user_agent, dst_info, count):
    # set up stats entries
    if src_ip not in stats:
        stats[src_ip] = {}
        stats[src_ip]['count'] = 0
        stats[src_ip]['fingerprints'] = {}
    if str_repr not in stats[src_ip]['fingerprints']:
        stats[src_ip]['fingerprints'][str_repr] = defaultdict(int)

    # update database counts
    stats[src_ip]['count'] += count
    stats[src_ip]['fingerprints'][str_repr]['count']  += count
    stats[src_ip]['fingerprints'][str_repr][user_agent] += count
    stats[src_ip]['fingerprints'][str_repr][dst_info] += count


def read_merc_data(in_file, mask_src_ip):
    stats_db    = {}
    total_count = 0
    addr_dict   = {}
    for line in open(in_file):
        r = json.loads(line)
        if 'fingerprints' not in r:
            continue

        src_ip      = r['src_ip']
        dst_ip      = r['dst_ip']
        dst_port    = r['dst_port']
        user_agent = ''

        # dictionary encode src_ip
        #
        if src_ip not in addr_dict:
            addr_dict[src_ip] = len(addr_dict)
        src_ip = addr_dict[src_ip]

        if mask_src_ip is True:
            src_ip = 0

        if 'tls' in r['fingerprints']:
            # extract data elements
            str_repr    = r['fingerprints']['tls']
            server_name = ''
            if 'client' in r['tls'] and 'server_name' in r['tls']['client']:
                server_name = r['tls']['client']['server_name']

            # update stats database
            update_stats_db(stats_db, src_ip, str_repr, user_agent, '({})({})({})'.format(server_name, dst_ip, dst_port), 1)
            total_count += 1

        if 'http' in r['fingerprints']:
            str_repr    = r['fingerprints']['http']
            if 'http' in r and 'request' in r['http'] and 'host' in r['http']['request']:
                server_name = r['http']['request']['host']
            else:
                print ('warning: http[request][host] missing')

            if 'http' in r and 'request' in r['http'] and 'user_agent' in r['http']['request']:
                user_agent = r['http']['request']['user_agent']
            else:
                print ('warning: http[request][user_agent] missing')

            # update stats database
            update_stats_db(stats_db, src_ip, str_repr, user_agent, '({})({})({})'.format(server_name, dst_ip, dst_port), 1)
            total_count += 1

        if 'quic' in r['fingerprints']:
            str_repr    = r['fingerprints']['quic']
            if 'tls' in r and 'client' in r['tls']:
                if 'server_name' in r['tls']['client']:
                    server_name = r['tls']['client']['server_name']

                if 'google_user_agent' in r['tls']['client']:
                    user_agent = r['tls']['client']['google_user_agent']

            # update stats database
            update_stats_db(stats_db, src_ip, str_repr, user_agent, '({})({})({})'.format(server_name, dst_ip, dst_port), 1)
            total_count += 1

    return stats_db, total_count


def read_merc_stats(in_file, mask_src_ip):
    stats_db    = {}
    total_count = 0
    for line in open(in_file):
        r = json.loads(line)
        src_ip = int(r['src_ip'], 16)  # convert hex string to integer

        if mask_src_ip is True:
            src_ip = 0

        for x in r['fingerprints']:
            str_repr = x['str_repr']
            sessions = x['sessions']
            for s in sessions:
                user_agent  = ''
                if 'user_agent' in s:
                    user_agent = s['user_agent']
                for y in s['dest_info']:
                    dst_info = y['dst']
                    count    = y['count']

                    # update stats database
                    update_stats_db(stats_db, src_ip, str_repr, user_agent, dst_info, count)
                    total_count += count

    return stats_db, total_count

def is_match(x, y):
    for str_repr, v in x['fingerprints'].items():
        for dst,_ in v.items():
            try:
                if x['fingerprints'][str_repr][dst] != y['fingerprints'][str_repr][dst]:
                    return False
            except KeyError:
                return False
    return True


def compare_stats_dbs(merc_db, merc_stats):
    if len(merc_db.keys()) != len(merc_stats.keys()):
        print('error: merc_db\'s src_ip\'s ({}) != merc_stat\'s src_ip\'s ({})'.format(len(merc_db.keys()), len(merc_stats.keys())))
        return False

    # find all potential matches for each src_ip
    potential_matches = defaultdict(list)
    for k,v in merc_db.items():
        for k1,v1 in merc_stats.items():
            if v['count'] == v1['count']:
                potential_matches[k].append(k1)

    # find exact matches for each src_ip
    matched_merc = set()
    matched_stat = set()
    for k,v in potential_matches.items():
        for k1 in v:
            if k1 in matched_stat:
                continue
            if is_match(merc_db[k], merc_stats[k1]):
                matched_merc.add(k)
                matched_stat.add(k1)
                break

    unmatched = False
    if len(matched_merc) != len(merc_db.keys()):
        unmatched = set(merc_db.keys()).difference(matched_merc)
        print('error: only ' + str(len(matched_merc)) + ' out of ' + str(len(merc_db.keys())) + ' merc_db src_ip\'s were matched:')
        for src_ip in unmatched:
            print('\t{}'.format(src_ip))
        unmatched = True

    if len(matched_stat) != len(merc_stats.keys()):
        unmatched = set(merc_stats.keys()).difference(matched_stat)
        print('error: only ' + str(len(matched_stat)) + ' out of ' + str(len(merc_stats.keys())) + ' merc_stat_db src_ip\'s were matched:')
        for src_ip in unmatched:
            print('\t{}'.format(src_ip))
        unmatched = True

    if unmatched:
        return False

    return True

def is_entry_match(x, y, unmatched_fps):
    for str_repr, v in x['fingerprints'].items():
        for dst,_ in v.items():
            try:
                if x['fingerprints'][str_repr][dst] > y['fingerprints'][str_repr][dst]:
                    unmatched_fps.append(str_repr + "-->" + dst)
                    return False
            except KeyError:
                unmatched_fps.append(str_repr)
                return False
    return True

def approx_stats_compare_db(merc_db, merc_stats):
    unmatched_fps = []
    for k,_ in merc_stats.items():
        if k not in merc_db:
            unmatched_fps.append(k)
            continue
        if merc_stats[k]['count'] > merc_db[k]['count']:
            unmatched_fps.append(k)
            continue

        is_entry_match(merc_stats[k], merc_db[k], unmatched_fps)

    if len(unmatched_fps):
        print('below fingerprint strings/destination parameters donot match')
        for x in unmatched_fps:
            print(x)
        return False

    return True

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-m','--mercury-output',action='store',dest='merc_out',
                      help='mercury output file',default=None)
    parser.add_argument('-d', '--directory-path', action='store', dest = 'path',
                      help='directory path for stats file', type=Path, default=os.getcwd())
    parser.add_argument('-s','--mercury-stats',action='store',dest='merc_stats',
                      help='mercury statistics file prefix',default=None)
    parser.add_argument('-i', '--ignore-src', action='store_true', dest='ignore_src_ip',
                      help='Ignore src ip while comparing',
                      default='False')
    parser.add_argument('-a', '--approx-match', action='store_true', dest='approx_match',
                      help='approximate match of stats and json entries',
                      default='False')

    args = parser.parse_args()
    if args.merc_out == None:
        print('error: specify mercury output file')
        sys.exit(1)
    if args.merc_stats == None:
        print('error: specify mercury statistics file')
        sys.exit(1)

    merc_db, merc_count = read_merc_data(args.merc_out, args.ignore_src_ip)
    # Locate all the stats file that starts with prefix merc_stats
    # Unzip the file(s) and store the extracted data in a temp file tempstats.json
    file_list = [filename for filename in os.listdir(str(args.path)) if filename.startswith(args.merc_stats)]

    fp = open("tempstats.json", "w+b")

    for f in file_list:
        with gzip.open(f) as file:
            data = file.read()
            fp.write(data)

    fp.close()

    merc_db_stats, merc_count_stats = read_merc_stats("tempstats.json", args.ignore_src_ip)

    if args.approx_match is True:
        if merc_count - merc_count_stats > 0.1 * merc_count:
            print('error: Difference between merc_out count ({}) and merc_stats count ({}) is greater then 10%'.format(merc_count, merc_count_stats))
            sys.exit(1)

        if approx_stats_compare_db(merc_db, merc_db_stats) == False:
            print('error: stats database comparison failed')
            sys.exit(1)

    else:
        if merc_count != merc_count_stats:
            print('error: merc_out count ({}) != merc_stats count ({})'.format(merc_count, merc_count_stats))
            sys.exit(1)

        # print(merc_count)
        # print(merc_count_stats)

        if compare_stats_dbs(merc_db, merc_db_stats) == False:
            print('error: stats database comparison failed')
            sys.exit(1)

    print('success: stats databases match')
    sys.exit(0)


if __name__ == "__main__":
    main()
