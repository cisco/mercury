#!/usr/bin/env python3

import os
import sys
import json
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
                    #src_ip = a['src_ip']
                    #dst_ip = a['dst_ip']
                    #event_start = a['event_start']
                    # compute maximum certificates present in a packet
                    if max_certs < len(cert_list):
                        max_certs = len(cert_list)

                    for c in cert_list:
                        pem_str = get_PEM_string(c)
                        cert_count += 1
                        #ofilename = "cert" + str(cert_count) + ".pem"
                        #with open(ofilename, "w") as ofile:
                        #    ofile.write(pem_str)

                        cert = get_certificate(pem_str)
                        if (cert == None):
                            bad_cert += 1
                            #print("bad cert_name {}, src_ip {}, dst_ip {} event_start {}\n".format(ofilename, src_ip, dst_ip, event_start))
                        else:
                            good_cert += 1
                            #print("cert_name {}, cert.serial_number {}\n".format(ofilename, cert.serial_number))

    return cert_count, good_cert, bad_cert, max_certs

def main():
    if len(sys.argv) != 2:
        print ("usage: " + sys.argv[0] + " <fingerprint file or directory>")
        return -1 # error
    inputfilename = sys.argv[1]

    cert_count = 0
    good_cert = 0
    bad_cert = 0
    max_certs = 0

    if (os.path.isfile(inputfilename)):
        cert_count1, good_cert1, bad_cert1, max_certs1 = process_json(inputfilename)
        cert_count += cert_count1
        good_cert += good_cert1
        bad_cert += bad_cert1
        if (max_certs < max_certs1):
            max_certs = max_certs1
    elif (os.path.isdir(inputfilename)):
        print("Processing directory {}...".format(inputfilename))
        file_list = os.listdir(inputfilename)
        for f in file_list:
            fname = os.path.join(inputfilename, f)
            cert_count1, good_cert1, bad_cert1, max_certs1 = process_json(fname)
            cert_count += cert_count1
            good_cert += good_cert1
            bad_cert += bad_cert1
            if (max_certs < max_certs1):
                max_certs = max_certs1
            print("  Processing file {}, Total certs {}, Complete certs {}, Partial certs {} ".format(
                fname, cert_count1, good_cert1, bad_cert1))

    print("Total Certs = {}, Complete certs = {}, Partial certs = {}".format(cert_count, good_cert, bad_cert))
    print("Max certs in a packet = {}".format(max_certs))

if __name__== "__main__":
    main()
