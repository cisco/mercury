#cython: language_level=3

import json
from base64 import b64decode

from libcpp.unordered_map cimport unordered_map
from libcpp.string cimport string
from libcpp cimport bool
from libc.stdio cimport *
from posix.time cimport timespec

### BUILD INSTRUCTIONS
# To build in-place:
#   CC=g++ python setup.py build_ext --inplace
# To build and install:
#   CC=g++ python setup.py install


# imports from mercury's dns
cdef extern from "../libmerc/dns.h":
    string dns_get_json_string(const char *dns_pkt, ssize_t pkt_len)


cdef extern from "../libmerc/pkt_proc.h":
    cdef struct mercury:
        pass
    cdef struct stateful_pkt_proc:
        pass

cdef extern from "../libmerc/result.h":
    cdef struct analysis_context:
        pass

cdef extern from "../libmerc/libmerc.h":
    cdef struct libmerc_config:
        bool do_analysis
        char* resources
    cdef struct mercury_context:
        pass
    cdef struct mercury_packet_processor:
        pass
    enum fingerprint_status:
        pass
    enum fingerprint_type:
        pass

    # mercury constructors/destructors
    mercury* mercury_init(const libmerc_config *vars, int verbosity)
    stateful_pkt_proc* mercury_packet_processor_construct(mercury_context mc)
    void mercury_packet_processor_destruct(mercury_packet_processor mpp)
    int mercury_finalize(mercury_context mc)

    # get analysis context
    analysis_context *mercury_packet_processor_get_analysis_context(mercury_packet_processor processor,
                                                                    unsigned char* packet, size_t length, timespec* ts)

    # get destination context
    const char *analysis_context_get_server_name(const analysis_context *ac)

    # get fingerprint info
    const char *analysis_context_get_fingerprint_string(const analysis_context *ac)
    fingerprint_status analysis_context_get_fingerprint_status(const analysis_context *ac)
    fingerprint_type analysis_context_get_fingerprint_type(const analysis_context *ac)

    # get process info
    bool analysis_context_get_process_info(const analysis_context *ac, const char **probable_process, double *probability_score)
    bool analysis_context_get_malware_info(const analysis_context *ac, bool *probable_process_is_malware, double *probability_malware)


fp_status_dict = {
    0: 'no_info_available',
    1: 'labeled',
    2: 'randomized',
    3: 'unlabled',
}
fp_type_dict = {
    0: 'unknown',
    1: 'tls',
    2: 'tls_server',
    3: 'http',
    4: 'http_server',
    5: 'ssh',
    6: 'ssh_kex',
    7: 'tcp',
    8: 'dhcp',
    9: 'smtp_server',
}

cdef class Mercury:
    cdef mercury* mercury_context
    cdef stateful_pkt_proc* mpp
    cdef const analysis_context* ac
    cdef timespec default_ts
    cdef dict py_config

    def __init__(self, bool do_analysis, bytes resources):
        self.py_config = {
            'do_analysis': do_analysis,
            'resources':   resources
        }
        self.default_ts.tv_sec = 0
        self.default_ts.tv_nsec = 0


    cpdef int mercury_init(self, unsigned int verbosity=0):
        cdef libmerc_config config = self.py_config
        self.mercury_context = mercury_init(&config, 0)
        if self.mercury_context == NULL:
            print('error: mercury_init() failed')
            return 1

        self.mpp = mercury_packet_processor_construct(<mercury_context>self.mercury_context)
        if self.mpp == NULL:
            print('error: mercury_packet_processor_construct() failed')
            return 1

        return 0


    cpdef dict analyze_packet(self, bytes pkt_data):
        cdef unsigned char* pkt_data_ref = pkt_data
        cdef const analysis_context* ac = mercury_packet_processor_get_analysis_context(<mercury_packet_processor>self.mpp,
                                                                                        pkt_data_ref, len(pkt_data), &self.default_ts);
        if ac == NULL:
            return None

        cdef dict result = {}

        server_name = self.get_server_name(ac)
        if server_name != None:
            result['tls'] = {}
            result['tls']['client'] = {}
            result['tls']['client']['server_name'] = server_name

        fp_status, fp_type, fp_string = self.get_fingerprint_info(ac)
        result['fingerprint_info'] = {}
        result['fingerprint_info']['status']   = fp_status
        result['fingerprint_info']['type']     = fp_type
        result['fingerprint_info']['str_repr'] = fp_string

        process_name, process_score, is_malware, prob_malware = self.get_process_info(ac)
        result['analysis'] = {}
        result['analysis']['process']   = process_name
        result['analysis']['score']     = process_score
        result['analysis']['malware']   = is_malware
        result['analysis']['p_malware'] = prob_malware

        return result


    cdef str get_server_name(self, const analysis_context* ac):
        cdef const char* server_name = analysis_context_get_server_name(ac)
        if server_name == NULL:
            return None
        return server_name.decode('UTF-8')


    cdef tuple get_fingerprint_info(self, const analysis_context* ac):
        cdef fingerprint_status fp_status = analysis_context_get_fingerprint_status(ac)
        cdef fingerprint_type fp_type = analysis_context_get_fingerprint_type(ac)
        cdef const char* fp_string = analysis_context_get_fingerprint_string(ac)

        return fp_status_dict[fp_status], fp_type_dict[fp_type], fp_string.decode('UTF-8')


    cdef tuple get_process_info(self, const analysis_context* ac):
        cdef double score, m_score
        cdef bool is_malware
        cdef const char* process_name = NULL
        cdef bool p = analysis_context_get_process_info(ac, &process_name, &score)
        cdef bool m = analysis_context_get_malware_info(ac, &is_malware, &m_score)
        if p and m:
            return process_name.decode('UTF-8'), score, is_malware, m_score
        elif p:
            return process_name.decode('UTF-8'), score, None, None
        else:
            return None, None, None, None


    cpdef int mercury_finalize(self):
        mercury_packet_processor_destruct(<mercury_packet_processor>self.mpp)
        cdef int retval = mercury_finalize(<mercury_context>self.mercury_context)
        return retval






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



# imports from mercury's asn1 parser
#cdef extern from "../libmerc/x509.h":
#    cdef struct x509_cert:
#        void parse(const void *buffer, unsigned int len)
#        string get_json_string()

#cdef extern from "../libmerc/x509.h":
#    cdef struct x509_cert_prefix:
#        void parse(const void *buffer, unsigned int len)
#        string get_hex_string()


# parse_cert
#  Input: b64_cert - python str representing a base64-encoded certificate
#  Output: JSON object containing parsed certificate
#def parse_cert(str b64_cert):
#    cdef bytes cert = b64decode(b64_cert)
#    cdef unsigned int len_ = len(cert)
#    cdef x509_cert x
#
#    # create reference to cert so that it doesn't get garbage collected
#    cdef char* c_string_ref = cert
#
#    # use mercury's asn1 parser to parse certificate data
#    x.parse(<const void*>c_string_ref, len_)
#
#    # get JSON string and return JSON object
#    return json.loads(x.get_json_string())


# get_cert_prefix
#  Input: b64_cert - python str representing a base64-encoded certificate
#  Output: string containing hex form of certificate prefix
#def get_cert_prefix(str b64_cert):
#    cdef bytes cert = b64decode(b64_cert)
#    cdef unsigned int len_ = len(cert)
#    cdef x509_cert_prefix x
#
#    # create reference to cert so that it doesn't get garbage collected
#    cdef char* c_string_ref = cert
#
#    # use mercury's asn1 parser to parse certificate data
#    x.parse(<const void*>c_string_ref, len_)
#
#    # return hex string
#    return x.get_hex_string()  # TBD: make it hex


