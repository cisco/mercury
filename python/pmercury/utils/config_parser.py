"""     
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from pmercury.utils.pmercury_utils import *



def parse_config(f_):
    protocols = set(['http','http_server'])

    config_file = find_resource_path(f_)
    if not os.path.exists(config_file):
        return None

    config = {}
    cur_proto = None
    cur_type  = None
    for line in open(config_file):
        line = line.strip()
        if line == '' or line.startswith('#'):
            continue

        if line in protocols:
            cur_proto = line
            continue

        if cur_proto not in config:
            config[cur_proto] = {}

        try:
            cur_type, params = line.split()
            config[cur_proto][cur_type] = params.split(',')
        except:
            print('error: unknown configuration file format (cur_proto)')
            return None

    return config

