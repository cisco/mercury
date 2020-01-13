"""
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import os
import sys
import yaml

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from pmercury.utils.pmercury_utils import *



def parse_config(f_):
    protocols = set(['http','http_server'])

    config_file = find_resource_path(f_)
    if not os.path.exists(config_file):
        return None

    with open(config_file, 'r') as yaml_cfg:
        config = yaml.safe_load(yaml_cfg)

    return config
