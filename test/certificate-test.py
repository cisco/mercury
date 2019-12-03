#!/usr/bin/env python3
#
# USAGE: certificate-test.py <json-filename>
#
# scans base64 encodes certificates, uses cryptography.x509 to create cert object.
#
# RETURN: 0 on success, nonzero otherwise

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
    end_str = '-----END CERTIFICATE-----'
    # as per RFC 7468, split base64 encoded string into 64 byte chunks
    c_str = '\n'.join(split_by_width(input_str, 64))
    cert_str = '\n'.join([begin_str, c_str, end_str])
    return cert_str

def get_certificate(cert_str):
    pem_str = get_PEM_string(cert_str)
    try:
        cert = x509.load_pem_x509_certificate(pem_str.encode('utf-8'), default_backend())
    except ValueError:
        #print('Value Error {}'.format(ve))
        return None
    else:
        return cert


def main():
    if len(sys.argv) != 2:
        print ("usage: " + sys.argv[0] + " <json file>")
        return -1 # error
    inputfilename = sys.argv[1]


    cert_count = 0
    good_cert = 0
    bad_cert = 0
    good_2nd_cert = 0
    bad_2nd_cert = 0
    with open(inputfilename) as f:
        for line in f:
            a = json.loads(line)
            if 'tls' in a:
                if 'server_certs' in a['tls']:
                    cert_no = 0
                    for c in a['tls']['server_certs']:
                        cert_count += 1
                        cert_no += 1
                        cert = get_certificate(c)
                        if (cert == None):
                            bad_cert += 1
                            if cert_no > 1:
                                bad_2nd_cert += 1
                        else:
                            good_cert += 1
                            #print("cert.serial_number {}".format(cert.serial_number))
                            if cert_no > 1:
                                good_2nd_cert += 1

    print("\nTotal Certs = {}, good certs = {}, bad certs = {}".format(cert_count, good_cert, bad_cert))
    print("\nGood 2nd certs = {}, bad 2nd certs = {}".format(good_2nd_cert, bad_2nd_cert))


if __name__== "__main__":
    main()
