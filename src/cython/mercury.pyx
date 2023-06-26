#cython: language_level=3

import json
from base64 import b64decode

from libcpp.unordered_map cimport unordered_map
from libcpp.string cimport string
from libcpp cimport bool
from libc.stdio cimport *
from libc.stdint cimport *
from libc.string cimport memset
from posix.time cimport timespec


### BUILD INSTRUCTIONS
# To build in-place:
#   CC=g++ python setup.py build_ext --inplace
# To build and install:
#   CC=g++ python setup.py install

# TODO: actually handle version
__version__ = '0.1.2'

# imports from mercury's dns
cdef extern from "../libmerc/dns.h":
    string dns_get_json_string(const char *dns_pkt, ssize_t pkt_len)


cdef extern from "../libmerc/pkt_proc.h":
    cdef struct mercury:
        pass
    cdef struct stateful_pkt_proc:
        pass

cdef extern from "../libmerc/libmerc.h":
    cdef struct libmerc_config:
        bool do_analysis
        char* resources
        bool output_tcp_initial_data
        bool output_udp_initial_data
        char* packet_filter_cfg
        bool metadata_output
        bool dns_json_output
        bool certs_json_output
    cdef struct mercury_context:
        pass
    cdef struct mercury_packet_processor:
        pass
    enum fingerprint_status:
        pass
    enum fingerprint_type:
        pass
    enum enc_key_type:
        enc_key_type_none

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

    # get json object
    size_t mercury_packet_processor_write_json(mercury_packet_processor processor, void *buffer, size_t buffer_size,
                                               uint8_t *packet, size_t length, timespec* ts)


cdef extern from "../libmerc/result.h":
    cdef cppclass attribute_result:
        void write_json(char *buffer, int buffer_size)
    cdef struct analysis_result:
        fingerprint_status status
        char max_proc[256]
        long double max_score
        bool max_mal
        long double malware_prob
        attribute_result attr
    cdef struct analysis_context:
        analysis_result result


cdef extern from "../libmerc/analysis.h":
    classifier *analysis_init_from_archive(int verbosity, const char *archive_name, const uint8_t *enc_key, enc_key_type key_type,
                                           float fp_proc_threshold, float proc_dst_threshold, bool report_os);
    cdef cppclass classifier:
        analysis_result perform_analysis(const char *fp_str, const char *server_name, const char *dst_ip, uint16_t dst_port, const char *user_agent)


fp_status_dict = {
    0: 'no_info_available',
    1: 'labeled',
    2: 'randomized',
    3: 'unlabled',
    4: 'unanalyzed',
}
fp_type_dict = {
    0:  'unknown',
    1:  'tls',
    2:  'tls_server',
    3:  'http',
    4:  'http_server',
    5:  'ssh',
    6:  'ssh_kex',
    7:  'tcp',
    8:  'dhcp',
    9:  'smtp_server',
    10: 'dtls',
    11: 'dtls_server',
    12: 'quic',
}

cdef class Mercury:
    cdef mercury* mercury_context
    cdef stateful_pkt_proc* mpp
    cdef const analysis_context* ac
    cdef timespec default_ts
    cdef dict py_config
    cdef classifier* clf
    cdef bool do_analysis

    def __init__(self, bool do_analysis=False, bytes resources=b'', bool output_tcp_initial_data=False, bool output_udp_initial_data=False,
                 bytes packet_filter_cfg=b'all', bool metadata_output=True, bool dns_json_output=True, bool certs_json_output=True):
        self.do_analysis = do_analysis
        self.py_config = {
            'output_tcp_initial_data': output_tcp_initial_data,
            'output_udp_initial_data': output_udp_initial_data,
            'packet_filter_cfg': packet_filter_cfg,
            'metadata_output': metadata_output,
            'dns_json_output': dns_json_output,
            'certs_json_output': certs_json_output,
            'do_analysis': do_analysis,
            'resources':   resources,
        }
        self.default_ts.tv_sec = 0
        self.default_ts.tv_nsec = 0

        cdef char* resources_c
        cdef enc_key_type ekt
        if do_analysis and resources != b'':
            resources_c = resources
            ekt = enc_key_type_none
            self.clf = analysis_init_from_archive(0, resources_c, NULL, ekt, 0.0, 0.0, False)

        self.mercury_init()


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


    cpdef dict get_mercury_json(self, bytes pkt_data):
        cdef unsigned char* pkt_data_ref = pkt_data

        cdef char buf[8192]
        memset(buf, 0, 8192)

        mercury_packet_processor_write_json(<mercury_packet_processor>self.mpp, buf, 8192, pkt_data_ref, len(pkt_data), &self.default_ts)

        cdef str json_str = buf.decode('UTF-8')
        if json_str != None:
            try:
                return json.loads(json_str.strip())
            except:
                return None
        else:
            return None


    cpdef dict get_fingerprint(self, bytes pkt_data):
        cdef unsigned char* pkt_data_ref = pkt_data
        cdef const analysis_context* ac = mercury_packet_processor_get_analysis_context(<mercury_packet_processor>self.mpp,
                                                                                        pkt_data_ref, len(pkt_data), &self.default_ts);
        if ac == NULL:
            return None

        cdef fingerprint_status fp_status = analysis_context_get_fingerprint_status(ac)
        cdef fingerprint_type fp_type = analysis_context_get_fingerprint_type(ac)
        cdef const char* fp_string = analysis_context_get_fingerprint_string(ac)

        result = {}
        result['status']   = fp_status_dict[fp_status]
        result['type']     = fp_type_dict[fp_type]
        result['str_repr'] = fp_string.decode('UTF-8')

        return result


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

        attributes = self.extract_attributes(ac.result)
        if len(attributes) > 0:
            result['analysis']['attributes'] = attributes

        return result


    cpdef dict perform_analysis(self, str fp_str, str server_name, str dst_ip, int dst_port):
        if not self.do_analysis:
            print(f'error: classifier not loaded (is do_analysis set to True?)')
            return None

        cdef bytes fp_str_b = fp_str.encode()
        cdef char* fp_str_c = fp_str_b
        cdef bytes server_name_b = server_name.encode()
        cdef char* server_name_c = server_name_b
        cdef bytes dst_ip_b = dst_ip.encode()
        cdef char* dst_ip_c = dst_ip_b

        cdef analysis_result ar = self.clf.perform_analysis(fp_str_c, server_name_c, dst_ip_c, dst_port, NULL)

        cdef fingerprint_status fp_status_enum = ar.status
        fp_status = fp_status_dict[fp_status_enum]

        cdef dict result = {}
        result['fingerprint_info'] = {}
        result['fingerprint_info']['status'] = fp_status
        result['analysis'] = {}
        result['analysis']['process']   = ar.max_proc.decode('UTF-8')
        result['analysis']['score']     = ar.max_score
        result['analysis']['malware']   = ar.max_mal
        result['analysis']['p_malware'] = ar.malware_prob

        attributes = self.extract_attributes(ar)
        if len(attributes) > 0:
            result['analysis']['attributes'] = attributes

        return result


    cdef list extract_attributes(self, analysis_result ar):
        cdef char tags_buf[8192]
        memset(tags_buf, 0, 8192)
        cdef char* tags_buf_p = tags_buf
        try:
            ar.attr.write_json(tags_buf_p, 8192)
            ret_ = []
            for x in json.loads(tags_buf_p.decode())['attributes']:
                ret_.append({'name': x['name'], 'probability_score': x['probability_score']})
            return ret_
        except:
            return []


    cpdef dict perform_analysis_with_user_agent(self, str fp_str, str server_name, str dst_ip, int dst_port, str user_agent):
        if not self.do_analysis:
            print(f'error: classifier not loaded (is do_analysis set to True?)')
            return None

        cdef bytes fp_str_b = fp_str.encode()
        cdef char* fp_str_c = fp_str_b
        if server_name == None:
            server_name = 'None'
        cdef bytes server_name_b = server_name.encode()
        cdef char* server_name_c = server_name_b
        cdef bytes dst_ip_b = dst_ip.encode()
        cdef char* dst_ip_c = dst_ip_b
        if user_agent == None:
            user_agent = 'None'
        cdef bytes user_agent_b = user_agent.encode()
        cdef char* user_agent_c = user_agent_b
        if user_agent == 'None':
            user_agent_c = NULL

        cdef analysis_result ar = self.clf.perform_analysis(fp_str_c, server_name_c, dst_ip_c, dst_port, user_agent_c)

        cdef fingerprint_status fp_status_enum = ar.status
        fp_status = fp_status_dict[fp_status_enum]

        cdef dict result = {}
        result['fingerprint_info'] = {}
        result['fingerprint_info']['status'] = fp_status
        result['analysis'] = {}
        result['analysis']['process']   = ar.max_proc.decode('UTF-8')
        result['analysis']['score']     = ar.max_score
        result['analysis']['malware']   = ar.max_mal
        result['analysis']['p_malware'] = ar.malware_prob

        attributes = self.extract_attributes(ar)
        if len(attributes) > 0:
            result['analysis']['attributes'] = attributes

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
cdef extern from "../libmerc/x509.h":
    cdef struct x509_cert:
        void parse(const void *buffer, unsigned int len)
        string get_json_string()
    cdef struct x509_cert_prefix:
        void parse(const void *buffer, unsigned int len)
        string get_hex_string()


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


