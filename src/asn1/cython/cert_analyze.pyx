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
cdef extern from "../x509.h":
    cdef struct x509_cert:
        void parse(const void *buffer, unsigned int len)
        string get_json_string()


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

