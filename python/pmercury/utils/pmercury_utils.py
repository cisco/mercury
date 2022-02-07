"""
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import os

def find_resource_path(rel_file_path):
    if rel_file_path == None:
        return None
    t = rel_file_path.split('/')
    rel_file_path = os.sep.join(t)

    p0 = os.path.dirname(os.path.abspath(__file__)) + os.sep+'..'+ os.sep+'..'+os.sep+'..'+os.sep + rel_file_path
    p1 = os.path.dirname(os.path.abspath(__file__)) + os.sep+'..'+os.sep+'..'+os.sep + rel_file_path
    p2 = os.path.dirname(os.path.abspath(__file__)) + os.sep+'..'+os.sep + rel_file_path
    p3 = os.path.dirname(os.path.abspath(__file__)) + os.sep + rel_file_path
    if os.path.exists(p0):
        return p0
    elif os.path.exists(p1):
        return p1
    elif os.path.exists(p2):
        return p2
    elif os.path.exists(p3):
        return p3
    else:
        return None


def find_path(rel_path):
    if rel_path == None:
        return None
    t = rel_path.split('/')
    rel_file_path = os.sep.join(t)

    p0 = os.path.dirname(os.path.abspath(__file__)) + os.sep+'..'+ os.sep+'..'+os.sep+'..'+os.sep + rel_path
    p1 = os.path.dirname(os.path.abspath(__file__)) + os.sep+'..'+os.sep+'..'+os.sep + rel_path
    p2 = os.path.dirname(os.path.abspath(__file__)) + os.sep+'..'+os.sep + rel_path
    p3 = os.path.dirname(os.path.abspath(__file__)) + os.sep + rel_path

    if os.path.exists(p0):
        return p0
    elif os.path.exists(p1):
        return p1
    elif os.path.exists(p2):
        return p2
    elif os.path.exists(p3):
        return p3
    else:
        return None

