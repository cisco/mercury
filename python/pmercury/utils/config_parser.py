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

        if line.startswith('--'):
            if cur_type == None:
                print('error: unknown configuration file format (cur_type)')
                return None
            config[cur_proto][cur_type].append(line.split('--')[1].strip())
        elif line.startswith('-'):
            if cur_proto == None:
                print('error: unknown configuration file format (cur_proto)')
                return None
            cur_type = line.split('-')[1].strip()
            config[cur_proto][cur_type] = []
        else:
            cur_proto = line
            config[cur_proto] = {}

    return config

