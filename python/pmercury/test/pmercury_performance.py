#!/usr/bin/env python3

"""
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import os
import sys
import pcap
import time
import optparse
import importlib
from importlib import machinery
from statistics import mean, stdev

sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../../')


def performance_test(input_file, output_file, fp_db, analyze, human_readable, experimental, group, num_procs, loops):
    print('Options:')
    print('\tAnalysis:\t%s' % analyze)
    print('\tHuman-Readable:\t%s' % human_readable)
    print('\tExperimental:\t%s' % experimental)
    print('\tGroup-Flows:\t%s' % group)
    print('\tNum-Procs:\t%s' % num_procs)
    print('\tLoops:\t\t%s\n' % loops)

    start = time.time()
    importlib.machinery.SOURCE_SUFFIXES.append('')
    pmercury = importlib.import_module('..pmercury','pmercury.pmercury')
    fp = pmercury.Fingerprinter(fp_db, output_file, analyze, num_procs,
                                human_readable, group, experimental, None)
    load_time = time.time() - start
    print('Initialization Time:\t%0.3fs' % load_time)

    loop_times = []
    for l in range(loops):
        start = time.time()
        fp.process_pcap(input_file)

        loop_time = time.time() - start
        loop_times.append(loop_time)
    if len(loop_times) > 1:
        print('Average Process Time:\t%0.3fs (+-%0.3fs)' % (mean(loop_times), stdev(loop_times)))
    else:
        print('Average Process Time:\t%0.3fs (+-%0.3fs)' % (loop_times[0], 0.0))
    fp.close_files()

    pcap_size = os.path.getsize(input_file)
    print('Bytes Processed:\t%0.2fM' % (pcap_size/1000000.))


def main():
    start = time.time()

    parser = optparse.OptionParser()

    parser.add_option('-r','--read',action='store',dest='pcap_file',
                      help='read packets from file',default=None)
    parser.add_option('-f','--fingerprint',action='store',dest='output',
                      help='write fingerprints to file',default=None)
    parser.add_option('-d','--fp_db',action='store',dest='fp_db',
                      help='location of fingerprint database',default='resources/fingerprint_db.json.gz')
    parser.add_option('-a','--analysis',action='store_true',dest='analyze',
                      help='perform process identification',default=False)
    parser.add_option('-w','--human-readable',action='store_true',dest='human_readable',
                      help='return human readable fingerprint information',default=False)
    parser.add_option('-x','--experimental',action='store_true',dest='experimental',
                      help='turns on all experimental features',default=False)
    parser.add_option('-g','--group-flows',action='store_true',dest='group',
                      help='aggregate packet-based fingerprints to flow-based',default=False)
    parser.add_option('-n','--num-procs',action='store',dest='num_procs',type='int',
                      help='return the top-n most probable processes',default=0)
    parser.add_option('-l','--loops',action='store',dest='loops',type='int',
                      help='loop over pcap n times',default=1)


    options, args = parser.parse_args()

    input_file = options.pcap_file
    performance_test(input_file, options.output, options.fp_db, options.analyze, options.human_readable,
                     options.experimental, options.group, options.num_procs, options.loops)




if __name__ == '__main__':
    sys.exit(main())
