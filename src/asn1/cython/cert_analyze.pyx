from libcpp.unordered_map cimport unordered_map
from libcpp.string cimport string
from libc.stdio cimport *


cdef extern from "../x509.h":
    cdef struct x509_cert:
        void parse(const void *buffer, unsigned int len)
        void print_as_json(FILE *f)


def process_cert(bytes cert, bytes fname):
    cdef unsigned int len_ = len(cert)
    cdef x509_cert x

    cdef char* c_string_ref = cert
    x.parse(<const void*>c_string_ref, len_)

    cdef FILE* out_file = fopen(fname, 'a')
    x.print_as_json(out_file)
    fclose(out_file)
