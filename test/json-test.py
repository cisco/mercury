#!/bin/python
#
# USAGE: json-test.py <jsonfilename>
#
# checks JSON file format for correctness against the mercury JSON schema
#
# RETURN: 0 on success, nonzero otherwise


import json
import sys

def test_mercury_json_line(line):
    x = json.loads(line)

    sa = x['sa']
    da = x['da']
    sp = x['sp']
    dp = x['dp']
    pr = x['pr']
    fingerprints = x['fingerprints']
    if 'tls' in fingerprints:
        tls = x['tls']
        sni = tls['sni']
    
def main():
    if len(sys.argv) != 2:
        print "usage: " + sys.argv[0] + " <jsonfilename>"
        return -1 # error
    inputfilename = sys.argv[1]
    
    for line in open(inputfilename):
        test_mercury_json_line(line)
    
  
if __name__== "__main__":
  main()
