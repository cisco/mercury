#!/bin/python
#
# USAGE: p-mercury-diff.py <mercury json output> <pmercury json output>
#
# checks JSON file format for correctness against the mercury JSON schema
#
# RETURN: 0 on success, nonzero otherwise


import sys
import json
import optparse
from collections import defaultdict


CONTEXTUAL_DATA_KEYS = ['tls','http','http_server']


def get_flow_key(record):
    return (f'{record["src_ip"]}::{record["src_port"]}::'
            f'{record["dst_ip"]}::{record["dst_port"]}::'
            f'{record["protocol"]}::{record["event_start"]}')


def get_keys(obj, k):
    if k in obj:
        return set(obj[k].keys())
    return set([])

def read_data(filename):
    total = 0
    db    = {}
    for line in open(filename, 'r'):
        total += 1

        record   = json.loads(line)
        flow_key = get_flow_key(record)
        db[flow_key] = record

    return total, db


def contextual_data_consistency(rec0, rec1, flow_key):
    matches    = {}
    mismatches = {}
    missing0   = {}
    missing1   = {}
    raw_data   = {}

    keys0 = set(rec0.keys())
    keys1 = set(rec1.keys())

    raw_data['mismatch'] = {}
    raw_data['missing0'] = {}
    raw_data['missing1'] = {}

    for k in CONTEXTUAL_DATA_KEYS:
        matches[k]    = defaultdict(int)
        mismatches[k] = defaultdict(int)
        missing0[k]   = defaultdict(int)
        missing1[k]   = defaultdict(int)

        raw_data['mismatch'][k] = defaultdict(list)
        raw_data['missing0'][k] = defaultdict(list)
        raw_data['missing1'][k] = defaultdict(list)

        keys0 = get_keys(rec0, k)
        keys1 = get_keys(rec1, k)

        for kv in keys1.difference(keys0):
            missing0[k][kv] += 1
            raw_data['missing0'][k][kv].append(('', rec1[k][kv], flow_key))

        for kv in keys0.difference(keys1):
            missing1[k][kv] += 1
            raw_data['missing1'][k][kv].append((rec0[k][kv], '', flow_key))

        for kv in keys0.intersection(keys1):
            if rec0[k][kv] == rec1[k][kv]:
                matches[k][kv] += 1
            else:
                mismatches[k][kv] += 1
                raw_data['mismatch'][k][kv].append((rec0[k][kv], rec1[k][kv], flow_key))

    return matches, mismatches, missing0, missing1, raw_data


def fingerprint_consistency(rec0, rec1, flow_key):
    matches    = defaultdict(int)
    mismatches = defaultdict(int)
    missing0   = defaultdict(int)
    missing1   = defaultdict(int)
    raw_data   = {}

    fps0   = {}
    fps1   = {}
    types0 = set([])
    types1 = set([])
    if 'fingerprints' in rec0:
        fps0 = rec0['fingerprints']
        types0 = set(fps0.keys())
    if 'fingerprints' in rec1:
        fps1 = rec1['fingerprints']
        types1 = set(fps1.keys())

    raw_data['mismatch'] = {}
    raw_data['missing0'] = {}
    raw_data['missing1'] = {}
    for k in types0.union(types1):
        raw_data['mismatch'][k] = []
        raw_data['missing0'][k] = []
        raw_data['missing1'][k] = []

    for k in types0.intersection(types1):
        if fps0[k] == fps1[k]:
            matches[k] += 1
        else:
            mismatches[k] += 1
            raw_data['mismatch'][k].append((fps0[k], fps1[k], flow_key))

    for k in types1.difference(types0):
        missing0[k] += 1
        raw_data['missing0'][k].append(('', fps1[k], flow_key))

    for k in types0.difference(types1):
        missing1[k] += 1
        raw_data['missing1'][k].append((fps0[k], '', flow_key))

    return matches, mismatches, missing0, missing1, raw_data


def consistency(keys, db0, db1):
    matches     = {}
    mismatches  = {}
    missing0    = {}
    missing1    = {}
    raw_data    = {}

    raw_data['fp'] = {}
    raw_data['fp']['mismatch'] = defaultdict(list)
    raw_data['fp']['missing0'] = defaultdict(list)
    raw_data['fp']['missing1'] = defaultdict(list)

    raw_data['ctx'] = {}
    raw_data['ctx']['mismatch'] = {}
    raw_data['ctx']['missing0'] = {}
    raw_data['ctx']['missing1'] = {}
    for k in CONTEXTUAL_DATA_KEYS:
        raw_data['ctx']['mismatch'][k] = defaultdict(list)
        raw_data['ctx']['missing0'][k] = defaultdict(list)
        raw_data['ctx']['missing1'][k] = defaultdict(list)

    matches['fp']     = defaultdict(int)
    matches['ctx']    = defaultdict(int)
    mismatches['fp']  = defaultdict(int)
    mismatches['ctx'] = defaultdict(int)
    missing0['fp']    = defaultdict(int)
    missing0['ctx']   = defaultdict(int)
    missing1['fp']    = defaultdict(int)
    missing1['ctx']   = defaultdict(int)

    for k in CONTEXTUAL_DATA_KEYS:
        matches['ctx'][k]    = defaultdict(int)
        mismatches['ctx'][k] = defaultdict(int)
        missing0['ctx'][k]   = defaultdict(int)
        missing1['ctx'][k]   = defaultdict(int)

    for k in keys:
        rec0 = {}
        rec1 = {}
        if k in db0:
            rec0 = db0[k]
        if k in db1:
            rec1 = db1[k]

        rmatches, rmismatches, rmissing0, rmissing1, rraw_data = fingerprint_consistency(rec0, rec1, k)
        for k0 in rmatches:
            matches['fp'][k0] += rmatches[k0]
        for k0 in rmismatches:
            mismatches['fp'][k0] += rmismatches[k0]
        for k0 in rmissing0:
            missing0['fp'][k0] += rmissing0[k0]
        for k0 in rmissing1:
            missing1['fp'][k0] += rmissing1[k0]
        for k0 in rraw_data:
            for k1 in rraw_data[k0]:
                for t in rraw_data[k0][k1]:
                    raw_data['fp'][k0][k1].append(t)

        rmatches, rmismatches, rmissing0, rmissing1, rraw_data = contextual_data_consistency(rec0, rec1, k)
        for k0 in rmatches:
            for kv in rmatches[k0]:
                matches['ctx'][k0][kv] += rmatches[k0][kv]
        for k0 in rmismatches:
            for kv in rmismatches[k0]:
                mismatches['ctx'][k0][kv] += rmismatches[k0][kv]
        for k0 in rmissing0:
            for kv in rmissing0[k0]:
                missing0['ctx'][k0][kv] += rmissing0[k0][kv]
        for k0 in rmissing1:
            for kv in rmissing1[k0]:
                missing1['ctx'][k0][kv] += rmissing1[k0][kv]
        for k0 in rraw_data:
            for k1 in rraw_data[k0]:
                for k2 in rraw_data[k0][k1]:
                    for t in rraw_data[k0][k1][k2]:
                        raw_data['ctx'][k0][k1][k2].append(t)

    return matches, mismatches, missing0, missing1, raw_data


def main():
    parser = optparse.OptionParser()

    parser.add_option('-m','--mercury',action='store',dest='fn0', help='mercury JSON output',default=None)
    parser.add_option('-p','--pmercury',action='store',dest='fn1', help='pmercury JSON output',default=None)
    parser.add_option('-q','--quiet',action='store_true',dest='quiet', help='only print general success/failure',default=False)
    parser.add_option('-n','--number',action='store',dest='n', help='print the top <n> failures',default=5)

    options, args = parser.parse_args()
    options.n = int(options.n)

    total0, db0 = read_data(options.fn0)
    total1, db1 = read_data(options.fn1)

    keys0 = set(db0.keys())
    keys1 = set(db1.keys())
    keys  = keys0.union(keys1)

    diff0 = keys0.difference(keys1)
    diff1 = keys1.difference(keys0)

    if options.quiet:
        if total0 == total1 and len(diff0) == 0 and len(diff1) == 0:
            print('success')
        else:
            print('failure')
        return 0

    print('total 0:\t\t% 8i' % total0)
    print('total 1:\t\t% 8i' % total1)
    print()

    print('additional keys in 0:\t% 8i' % len(diff0))
    print('additional keys in 1:\t% 8i' % len(diff1))
    print()

    matches, mismatches, missing0, missing1, raw_data = consistency(keys, db0, db1)

    print('MATCHING DATA SUMMARY')
    print('---------------------')

    print('matching fingerprint strings by protocol:')
    for k in matches['fp']:
        print('\t% 12s\t% 8i' % (k+':', matches['fp'][k]))
    print()

    print('matching contextual data by protocol:')
    for k in matches['ctx']:
        print('\t% 12s' % k)
        for kv in matches['ctx'][k]:
            print('\t\t% 20s\t% 8i' % (kv+':', matches['ctx'][k][kv]))
    print()

    print()
    print('MISMATCHING DATA SUMMARY')
    print('------------------------')

    print('mismatching fingerprint strings by protocol:')
    for k in mismatches['fp']:
        print('\t% 12s\t% 8i' % (k+':', mismatches['fp'][k]))
    print()

    print('mismatching contextual data by protocol:')
    for k in mismatches['ctx']:
        print('\t% 12s' % k)
        for kv in mismatches['ctx'][k]:
            print('\t\t% 20s\t% 8i' % (kv+':', mismatches['ctx'][k][kv]))
    print()

    print()
    print('MISSING DATA SUMMARY')
    print('--------------------')

    print('fingerprint strings missing in file_0 by protocol:')
    for k in missing0['fp']:
        print('\t% 12s\t% 8i' % (k+':', missing0['fp'][k]))
    print()

    print('fingerprint strings missing in file_1 by protocol:')
    for k in missing1['fp']:
        print('\t% 12s\t% 8i' % (k+':', missing1['fp'][k]))
    print()

    print('contextual data missing in file_0 by protocol:')
    for k in missing0['ctx']:
        print('\t% 12s' % k)
        for kv in missing0['ctx'][k]:
            print('\t\t% 20s\t% 8i' % (kv+':', missing0['ctx'][k][kv]))
    print()
    print('contextual data missing in file_1 by protocol:')
    for k in missing1['ctx']:
        print('\t% 12s' % k)
        for kv in missing1['ctx'][k]:
            print('\t\t% 20s\t% 8i' % (kv+':', missing1['ctx'][k][kv]))
    print()


    print()
    print('MISMATCHING DATA')
    print('----------------')

    print('mismatching fingerprint strings by protocol:')
    for k in raw_data['fp']['mismatch']:
        if len(raw_data['fp']['mismatch'][k]) > 0:
            print('\t% 12s' % k)
            for fp0,fp1,fk in raw_data['fp']['mismatch'][k][0:options.n]:
                print('\t\tfp0:\t%s' % fp0)
                print('\t\tfp1:\t%s' % fp1)
                print('\t\tkey:\t%s' % fk)
                print()

    print()
    print('mismatching contextual data by protocol:')
    for k in raw_data['ctx']['mismatch']:
        print('\t% 12s' % k)
        for k1 in raw_data['ctx']['mismatch'][k]:
            if len(raw_data['ctx']['mismatch'][k][k1]) > 0:
                print('\t\t% 12s' % k1)
                for fp0,fp1,fk in raw_data['ctx']['mismatch'][k][k1][0:options.n]:
                    print('\t\t\tcd0:\t%s' % fp0)
                    print('\t\t\tcd1:\t%s' % fp1)
                    print('\t\t\tkey:\t%s' % fk)
                    print()


    print()
    print('MISSING 0 DATA')
    print('--------------')
    print('missing fingerprint strings by protocol:')
    for k in raw_data['fp']['missing0']:
        if len(raw_data['fp']['missing0'][k]) > 0:
            print('\t% 12s' % k)
            for fp0,fp1,fk in raw_data['fp']['missing0'][k][0:options.n]:
                print('\t\tfp0:\t%s' % fp0)
                print('\t\tfp1:\t%s' % fp1)
                print('\t\tkey:\t%s' % fk)
                print()

    print()
    print('missing contextual data by protocol:')
    for k in raw_data['ctx']['missing0']:
        print('\t% 12s' % k)
        for k1 in raw_data['ctx']['missing0'][k]:
            if len(raw_data['ctx']['missing0'][k][k1]) > 0:
                print('\t\t% 12s' % k1)
                for fp0,fp1,fk in raw_data['ctx']['missing0'][k][k1][0:options.n]:
                    print('\t\t\tcd0:\t%s' % fp0)
                    print('\t\t\tcd1:\t%s' % fp1)
                    print('\t\t\tkey:\t%s' % fk)
                    print()

    print()
    print('MISSING 1 DATA')
    print('--------------')
    print('missing fingerprint strings by protocol:')
    for k in raw_data['fp']['missing1']:
        if len(raw_data['fp']['missing1'][k]) > 0:
            print('\t% 12s' % k)
            for fp0,fp1,fk in raw_data['fp']['missing1'][k][0:options.n]:
                print('\t\tfp0:\t%s' % fp0)
                print('\t\tfp1:\t%s' % fp1)
                print('\t\tkey:\t%s' % fk)
                print()

    print()
    print('missing contextual data by protocol:')
    for k in raw_data['ctx']['missing1']:
        print('\t% 12s' % k)
        for k1 in raw_data['ctx']['missing1'][k]:
            if len(raw_data['ctx']['missing1'][k][k1]) > 0:
                print('\t\t% 12s' % k1)
                for fp0,fp1,fk in raw_data['ctx']['missing1'][k][k1][0:options.n]:
                    print('\t\t\tcd0:\t%s' % fp0)
                    print('\t\t\tcd1:\t%s' % fp1)
                    print('\t\t\tkey:\t%s' % fk)
                    print()


if __name__== "__main__":
  main()

