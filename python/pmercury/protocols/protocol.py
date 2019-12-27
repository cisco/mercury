"""
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

class Protocol:

    # returns fingerprint, approximate fingerprint, contextual data
    def fingerprint(self, data):
        return None, None

    def proc_identify(self, fp_str_, context_, dst_ip, dst_port, list_procs=5, prev_flow=None):
        return None

    def gen_unknown_fingerprint(self, fp_str_):
        return None

    def get_human_readable(self, fp_str_):
        return None

    def get_approx_fingerprint(self, fp_str_):
        return None
