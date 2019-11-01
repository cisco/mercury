import os


def find_resource_path(rel_file_path):
    p0 = os.path.dirname(os.path.abspath(__file__)) + '/../../../' + rel_file_path
    p1 = os.path.dirname(os.path.abspath(__file__)) + '/../../' + rel_file_path
    p2 = os.path.dirname(os.path.abspath(__file__)) + '/../' + rel_file_path
    if os.path.exists(p0):
        return p0
    elif os.path.exists(p1):
        return p1
    elif os.path.exists(p2):
        return p2
    else:
        return os.path.dirname(os.path.abspath(__file__)) + '/' + rel_file_path

