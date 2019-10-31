#!/bin/python
#
# USAGE: json-test-v2.py <jsonfilename>
#
# checks JSON file format for correctness against the mercury JSON schema
#
# RETURN: 0 on success, nonzero otherwise


import jsonschema
import json
import sys

mercury_schema = {
    'type':       'object',
    'properties': {
        'src_ip':       {'type': 'string'},
        'dst_ip':       {'type': 'string'},
        'src_port':     {'type': 'number'},
        'dst_port':     {'type': 'number'},
        'protocol':     {'type': 'number'},
        'event_start':  {'type': 'number'},
        'fingerprints': {'type': 'object',
                         'properties': {
                             'tls': {'type': 'string'},
                             'tcp': {'type': 'string'},
                         },
        },
        'tls': {'type': 'object',
                'properties': {
                    'server_name': {'type': 'string'},
                }
        }
    },
    'required': ['src_ip','dst_ip','src_port','dst_port','protocol','event_start','fingerprints']
}


def test_mercury_json_line(line):
    try:
        jsonschema.validate(instance=json.loads(line), schema=mercury_schema)
    except Exception as e:
        print(e)
        return -1

    return 0


def main():
    if len(sys.argv) != 2:
        print('usage: %s <jsonfilename>' % sys.argv[0])
        return -1 # error
    inputfilename = sys.argv[1]

    total  = 0
    failed = 0
    for line in open(inputfilename):
        ret = test_mercury_json_line(line)
        total += 1
        if ret == -1:
            failed += 1

    print('%% Failed:\t%0.2f%%' % (100.*failed/float(total)))


if __name__== "__main__":
  main()
