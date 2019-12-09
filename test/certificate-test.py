#!/usr/bin/env python3

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


def main():
    if len(sys.argv) != 2:
        print ("usage: " + sys.argv[0] + " <fingerprint file>")
        return -1 # error
    inputfilename = sys.argv[1]


    cert_count = 0
    good_cert = 0
    bad_cert = 0
    max_certs = 0
    with open(inputfilename) as f:
        for line in f:
            a = json.loads(line)
            if 'tls' in a:
                if 'server_certs' in a['tls']:
                    cert_list = a['tls']['server_certs']
                    
                    # compute maximum certificates present in a packet
                    if max_certs < len(cert_list):
                        max_certs = len(cert_list)

                    for c in cert_list:
                        cert_count += 1
                        pem_str = get_PEM_string(c)

                        ofilename = "cert" + str(cert_count) + ".pem"
                        with open(ofilename, "w") as ofile:
                            ofile.write(pem_str)

                        cert = get_certificate(pem_str)
                        if (cert == None):
                            bad_cert += 1
                        else:
                            good_cert += 1
                            print("cert_name {}, cert.serial_number {}".format(ofilename, cert.serial_number))

    print("Total Certs = {}, good certs = {}, bad certs = {}".format(cert_count, good_cert, bad_cert))
    print("max certs in a packet = {}".format(max_certs))


if __name__== "__main__":
    main()
