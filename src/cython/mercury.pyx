#cython: language_level=3

import json
from base64 import b64decode

from libcpp.unordered_map cimport unordered_map
from libcpp.string cimport string
from libc.stdio cimport *

### BUILD INSTRUCTIONS
# To build in-place:
#   CC=g++ python setup.py build_ext --inplace
# To build and install:
#   CC=g++ python setup.py install


# imports from mercury's asn1 parser
cdef extern from "../libmerc/x509.h":
    cdef struct x509_cert:
        void parse(const void *buffer, unsigned int len)
        string get_json_string()

cdef extern from "../libmerc/x509.h":
    cdef struct x509_cert_prefix:
        void parse(const void *buffer, unsigned int len)
        string get_hex_string()

# imports from mercury's dns
cdef extern from "../libmerc/dns.h":
    string dns_get_json_string(const char *dns_pkt, ssize_t pkt_len)



# parse_cert
#  Input: b64_cert - python str representing a base64-encoded certificate
#  Output: JSON object containing parsed certificate
def parse_cert(str b64_cert):
    cdef bytes cert = b64decode(b64_cert)
    cdef unsigned int len_ = len(cert)
    cdef x509_cert x

    # create reference to cert so that it doesn't get garbage collected
    cdef char* c_string_ref = cert

    # use mercury's asn1 parser to parse certificate data
    x.parse(<const void*>c_string_ref, len_)

    # get JSON string and return JSON object
    return json.loads(x.get_json_string())


# get_cert_prefix
#  Input: b64_cert - python str representing a base64-encoded certificate
#  Output: string containing hex form of certificate prefix
def get_cert_prefix(str b64_cert):
    cdef bytes cert = b64decode(b64_cert)
    cdef unsigned int len_ = len(cert)
    cdef x509_cert_prefix x

    # create reference to cert so that it doesn't get garbage collected
    cdef char* c_string_ref = cert

    # use mercury's asn1 parser to parse certificate data
    x.parse(<const void*>c_string_ref, len_)

    # return hex string
    return x.get_hex_string()  # TBD: make it hex


# parse_dns
#  Input: b64_dns - python str representing a base64-encoded DNS request
#  Output: JSON object containing parsed DNS request
def parse_dns(str b64_dns):
    cdef bytes dns_req = b64decode(b64_dns)
    cdef unsigned int len_ = len(dns_req)

    # create reference to dns so that it doesn't get garbage collected
    cdef char* c_string_ref = dns_req

    # use mercury's dns parser to parse the DNS request
    return json.loads(dns_get_json_string(c_string_ref, len_))

