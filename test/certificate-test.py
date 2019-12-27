#!/bin/python

import os
import sys
import json
import argparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def split_by_width(input_str, width):
    out_list = []
    s1 = input_str
    while(len(s1) > width):
        s2 = s1[:width]
        out_list.append(s2)
        s1 = s1[width:]
    out_list.append(s1)
    return out_list

def get_PEM_string(input_str):
    begin_str = '-----BEGIN CERTIFICATE-----'
    end_str = '-----END CERTIFICATE-----\n'
    # as per RFC 7468, split base64 encoded string into 64 byte chunks
    c_str = '\n'.join(split_by_width(input_str, 64))
    cert_str = '\n'.join([begin_str, c_str, end_str])
    return cert_str

def get_certificate(pem_str):
    try:
        cert = x509.load_pem_x509_certificate(pem_str.encode('utf-8'), default_backend())
    except ValueError:
        #print('Value Error {}'.format(ve))
        return None
    else:
        return cert

def process_json(json_file):
    cert_count = 0
    good_cert = 0
    bad_cert = 0
    max_certs = 0
    with open(json_file) as f:
        for line in f:
            a = json.loads(line)
            if 'tls' in a:
                if 'server_certs' in a['tls']:
                    cert_list = a['tls']['server_certs']
                    # compute maximum certificates present in a packet
                    if max_certs < len(cert_list):
                        max_certs = len(cert_list)
                    for c in cert_list:
                        pem_str = get_PEM_string(c)
                        cert_count += 1
                        cert = get_certificate(pem_str)
                        if (cert == None):
                            bad_cert += 1
                        else:
                            good_cert += 1
                            #ofilename = "cert" + str(cert_count) + ".pem"
                            #with open(ofilename, "w") as ofile:
                            #    ofile.write(pem_str)
                            #print("cert_name {}, cert.serial_number {}\n".format(ofilename, cert.serial_number))

    return cert_count, good_cert, bad_cert, max_certs

def main():
    # process arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("file", help="json file or directory with json files")
    parser.add_argument("--complete", type=int,
                        help="Expected number of complete Certificates")
    parser.add_argument("--partial", type=int,
                        help="Expected number of partial Certificates")
    args = parser.parse_args()
    inputfilename = args.file

    cert_count = 0
    good_cert = 0
    bad_cert = 0
    max_certs = 0

    if (os.path.isfile(inputfilename)):
        print("Processing file {}...".format(inputfilename))
        cert_count1, good_cert1, bad_cert1, max_certs1 = process_json(inputfilename)
        cert_count += cert_count1
        good_cert += good_cert1
        bad_cert += bad_cert1
        if (max_certs < max_certs1):
            max_certs = max_certs1
    elif (os.path.isdir(inputfilename)):
        print("Processing directory {}...".format(inputfilename))
        os.chdir(inputfilename)
        file_list = [ f for f in os.listdir(os.curdir) if os.path.isfile(f) ]
        for f in file_list:
            cert_count1, good_cert1, bad_cert1, max_certs1 = process_json(f)
            cert_count += cert_count1
            good_cert += good_cert1
            bad_cert += bad_cert1
            if (max_certs < max_certs1):
                max_certs = max_certs1
            print("  Processing file {}, Total certs {}, Complete certs {}, Partial certs {} ".format(
                f, cert_count1, good_cert1, bad_cert1))

    print("Total Certs = {}, Complete certs = {}, Partial certs = {}".format(cert_count, good_cert, bad_cert))
    print("  Max certs in a packet = {}".format(max_certs))

    # if expected complete certs and partial certs are given, verify the results
    if (args.complete or args.partial):
        if ((not args.complete or args.complete == good_cert)
            and (not args.partial or args.partial == bad_cert)):
            print("Success!")
            sys.exit(0)
        else:
            print("Failure: did not match the expected value")
            sys.exit(1)

if __name__== "__main__":
    main()
