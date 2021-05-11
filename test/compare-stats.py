import sys
import json
import argparse
from collections import defaultdict


def update_stats_db(stats, src_ip, str_repr, dst_info, count):
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
    stats[src_ip]['fingerprints'][str_repr][dst_info] += count


def read_merc_data(in_file):
    stats_db    = {}
    total_count = 0
    for line in open(in_file):
        r = json.loads(line)
        if 'fingerprints' not in r or 'tls' not in r['fingerprints']:
            continue

        # extract data elements
        str_repr    = r['fingerprints']['tls']
        src_ip      = r['src_ip']
        dst_ip      = r['dst_ip']
        dst_port    = r['dst_port']
        server_name = ''
        if 'client' in r['tls'] and 'server_name' in r['tls']['client']:
            server_name = r['tls']['client']['server_name']

        # update stats database
        update_stats_db(stats_db, src_ip, str_repr, f'({server_name})({dst_ip})({dst_port})', 1)
        total_count += 1

    return stats_db, total_count


def read_merc_stats(in_file):
    stats_db    = {}
    total_count = 0
    for line in open(in_file):
        r = json.loads(line)
        src_ip = r['src_ip']
        for x in r['fingerprints']:
            str_repr = x['str_repr'][1:-1] # TODO: delete [1:-1], not needed if there aren't extra parens
            for y in x['dest_info']:
                dst_info = y['dst']
                count    = y['count']

                # update stats database
                update_stats_db(stats_db, src_ip, str_repr, dst_info, count)
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
        print(f'error: merc_db\'s src_ip\'s ({len(merc_db.keys())}) != merc_stat\'s src_ip\'s ({len(merc_stats.keys())})')
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
        print(f'error: not all stats src_ip\'s were matched:')
        for src_ip in unmatched:
            print(f'\t{src_ip}')
        unmatched = True

    if len(matched_stat) != len(merc_stats.keys()):
        unmatched = set(merc_stats.keys()).difference(matched_stat)
        print(f'error: not all stats src_ip\'s were matched:')
        for src_ip in unmatched:
            print(f'\t{src_ip}')
        unmatched = True

    if unmatched:
        return False

    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-m','--mercury-output',action='store',dest='merc_out',
                      help='mercury output file',default=None)
    parser.add_argument('-s','--mercury-stats',action='store',dest='merc_stats',
                      help='mercury statistics file',default=None)

    args = parser.parse_args()
    if args.merc_out == None:
        print('error: specify mercury output file')
        sys.exit(1)
    if args.merc_stats == None:
        print('error: specify mercury statistics file')
        sys.exit(1)

    merc_db, merc_count             = read_merc_data(args.merc_out)
    merc_db_stats, merc_count_stats = read_merc_stats(args.merc_stats)

    if merc_count != merc_count_stats:
        print(f'error: merc_out count ({merc_count}) != merc_stats count ({merc_count_stats})')
        sys.exit(1)

    print(merc_count)
    print(merc_count_stats)

    if compare_stats_dbs(merc_db, merc_db_stats) == False:
        print('error: stats database comparison failed')
        sys.exit(1)

    print('success: stats databases match!')
    sys.exit(0)


if __name__ == "__main__":
    main()
