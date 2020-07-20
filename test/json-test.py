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
        'complete':     {'type': 'string'},
        'fingerprints': {'type': 'object',
                         'properties': {
                             'tcp':         {'type': 'string'},
                             'tls':         {'type': 'string'},
                             'tls_server':  {'type': 'string'},
                             'dtls':        {'type': 'string'},
                             'dtls_server': {'type': 'string'},
                             'http':        {'type': 'string'},
                             'http_server': {'type': 'string'},
                             'dhcp':        {'type': 'string'},
                         },
                         "additionalProperties": False
        },
        'tls': {'type': 'object',
                'properties': {
                    'client': {
                        'type': 'object',
                        'properties': {
                            'server_name': {'type': 'string'}
                        }
                    },
                    'server': {
                        'properties': {
                            'certs': {'type': 'array',
                                     'items': {
                                         'type': 'object',
                                         'properties': {
                                             'base64': { 'type': 'string'},
                                             'cert': { ' type': 'object' }
                                         }
                                     }
                            }
                        }
                    }
                },
                "additionalProperties": False
            },
        'http': {'type': 'object',
                 'properties': {
                     'host':            {'type': 'string'},
                     'user_agent':      {'type': 'string'},
                     'x-forwarded-for': {'type': 'string'}
                 },
                 "additionalProperties": False
             },
        'http_server': {'type': 'object',
                        'properties': {
                            'via': {'type': 'string'}
                        },
                        "additionalProperties": False
                    },
        'dhcp': {'type': 'object',
                 'properties': {
                     'client_mac_address': {'type': 'string'},
                     'router':             {'type': 'string'},
                     'domain_name_server': {'type': 'string'},
                     'hostname':           {'type': 'string'},
                     'domain_name':        {'type': 'string'},
                     'requested_ip':       {'type': 'string'},
                     'vendor_class_id':    {'type': 'string'},
                 },
                 "additionalProperties": False
             },
        'analysis': {'type': 'object',
                     'properties': {
                         'process':   {'type': 'string'},
                         'category':  {'type': 'string'},
                         'score':     {'type': 'number'},
                         'malware':   {'type': 'number'},
                         'p_malware': {'type': 'number'},
                     },
                     "additionalProperties": False
             },
        'dns': {'type': 'object',
                     'properties': {
                         'base64':   {'type': 'string'},
                         'response': {'type': 'object'},
                     },
                     "additionalProperties": False
             }
    },
    'required': ['src_ip','dst_ip','src_port','dst_port','protocol','event_start'],
    "additionalProperties": False
}


def test_mercury_json_line(line):
    try:
        jsonschema.validate(instance=json.loads(line), schema=mercury_schema)
    except Exception as e:
        print(e)
        return -1

    return 0


def main():
    if len(sys.argv) != 2 or sys.argv[1] == '--help':
        print('usage: %s <jsonfilename>' % sys.argv[0])
        return -1
    inputfilename = sys.argv[1]

    total  = 0
    failed = 0
    for line in open(inputfilename):
        ret = test_mercury_json_line(line)
        total += 1
        if ret == -1:
            failed += 1

    print('%% Failed:\t%0.2f%%' % (100.*failed/float(total)))
    if (failed > 0):
        sys.exit(1)
    else:
        sys.exit(0)

if __name__== "__main__":
  main()

