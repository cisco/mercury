"""
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import os
import sys
import pyasn
import pickle
import functools

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from pmercury.utils.pmercury_utils import *


MAX_CACHED_RESULTS = 2**24



tlds = set([])

if os.name == 'nt':
    import gzip
    public_suffix_file_raw = find_resource_path('resources/public_suffix_list.dat.gz')
    for line in gzip.open(public_suffix_file_raw, 'r'):
        line = line.strip()
        if line.startswith(b'//') or line == b'':
            continue
        if line.startswith(b'*'):
            line = line[2:]
        tlds.add(line.decode())
else:
    public_suffix_file_raw = find_resource_path('resources/public_suffix_list.dat.gz')
    for line in os.popen('zcat %s' % (public_suffix_file_raw)):
        line = line.strip()
        if line.startswith('//') or line == '':
            continue
        if line.startswith('*'):
            line = line[2:]
        tlds.add(line)


pyasn_context_file    = find_resource_path('resources/pyasn.db')
pyasn_contextual_data = pyasn.pyasn(pyasn_context_file)


port_mapping = {
    443:  'https',     448:  'database',  465:  'email',     563:  'nntp',      585:  'email',
    614:  'shell',     636:  'ldap',      989:  'ftp',       990:  'ftp',       991:  'nas',
    992:  'telnet',    993:  'email',     994:  'irc',       995:  'email',     1443: 'alt-https',
    2376: 'docker',    8001: 'tor',       8443: 'alt-https', 9000: 'tor',       9001: 'tor',
    9002: 'tor',       9101: 'tor',
}



@functools.lru_cache(maxsize=MAX_CACHED_RESULTS)
def get_tld_info(hostname):
    if hostname == None or hostname == 'None':
        return 'None', 'None'
    tokens_ = hostname.split('.')
    tld_ = tokens_[-1]
    tmp_tld_ = tokens_[-1]
    domain_ = tokens_[-1]
    tmp_domain_ = tokens_[-1]
    if len(tokens_) > 1:
        domain_ = tokens_[-2] + '.' + domain_
        tmp_domain_ = tokens_[-2] + '.' + tmp_domain_
    for i in range(2,7):
        if len(tokens_) < i:
            return domain_, tld_
        if len(tokens_) > i:
            tmp_domain_ = tokens_[(i+1)*-1] + '.' + tmp_domain_
        tmp_tld_ = tokens_[i*-1] + '.' + tmp_tld_
        if tmp_tld_ in tlds:
            domain_ = tmp_domain_
            tld_ = tmp_tld_

    return domain_, tld_


@functools.lru_cache(maxsize=MAX_CACHED_RESULTS)
def get_asn_info(ip_addr):
    asn,_ = pyasn_contextual_data.lookup(ip_addr)
    if asn != None:
        return str(asn)

    return 'unknown'


def get_port_application(port):
    port_class = 'unknown'
    if port in port_mapping:
        port_class = port_mapping[port]

    return port_class

