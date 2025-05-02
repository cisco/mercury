#cython: language_level=3, embedsignature=True

import json
import math
from base64 import b64decode

from libcpp.unordered_map cimport unordered_map
from libcpp.string cimport string
from libcpp cimport bool
from libc.stdio cimport *
from libc.stdint cimport *
from libc.string cimport memset
from posix.time cimport timespec
from cython.operator import dereference


"""
:mod:`mercury-python` -- Packet parser
===================================

.. module:: mercury
   :platform: Unix
   :synopsis: A cython-based interface into mercury's functionality
"""


### BUILD INSTRUCTIONS
# To build in-place:
#   CC=g++ CXX=g++ python setup.py build_ext --inplace
# To build and install:
#   CC=g++ CXX=g++ python setup.py install

# TODO: actually handle version
__version__ = '2.7.0'

# imports from mercury's dns
cdef extern from "../libmerc/dns.h":
    string dns_get_json_string(const char *dns_pkt, ssize_t pkt_len)

# imports from mercury's FDC
cdef extern from "../libmerc/fdc.hpp":
    string get_json_decoded_fdc(const char *fdc_blob, ssize_t blob_len)


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

        # analysis_result perform_analysis_with_weights(const char *fp_str, const char *server_name, const char *dst_ip, uint16_t dst_port, const char *user_agent,
        #                         long double new_as_weight, long double new_domain_weight,
        #                         long double new_port_weight, long double new_ip_weight,
        #                         long double new_sni_weight, long double new_ua_weight)


cdef extern from "../libmerc/watchlist.hpp":
    string normalize_ip_address(const string &s)
    cdef cppclass server_identifier:
        server_identifier(string &s)
        enum detail:
            off=0,
            on
        string get_normalized_domain_name(detail detailed_output)


cdef class server_identifier_py:
    cdef server_identifier* thisptr
    cdef server_identifier.detail detailed_output

    def __cinit__(self, s):
        self.thisptr = new server_identifier(s.encode('utf-8'))

    def get_normalized_domain_name(self, bool detailed_output=True):
        self.detailed_output = <server_identifier.detail>detailed_output
        try:
            return self.thisptr.get_normalized_domain_name(self.detailed_output).decode()
        except Exception as e:
            print(f'Exception: {e}')
            return None


def get_normalized_domain_name(str domain_name, bool detailed_output=True):
    """returns a python str representing a host or server name,
    normalized so that textual representations of IPv4 or IPv6 addresses
    are mapped into an .alt pseudo-DNS namespace.

    :param domain_name: python str representing a domain name (HTTP Host, TLS or QUIC Server Name)

    :param detailed_output:  if true, the address literal is included in the normalized name

    :returns: normalized name string
    """
    si = server_identifier_py(domain_name)
    return si.get_normalized_domain_name(detailed_output)


def get_normalized_ip_address(str ip_address):
    """returns a python str representing an IPv4 or IPv6 address,
    normalized by setting it to `10.0.0.1` if it is in the IPv4
    private address range (RFC 1918), or setting it to `fd00::1` if it
    is in the IPv6 unique local address range (RFC 4193).  The IPv4
    private address ranges consist of the subnets `10.0.0.0/8`,
    `172.16.0.0/12`, and `192.168.0.0/16`.  The IPv6 unique local
    address range consists of the subnet `fd00::/8`.

    :param ip_address: python str containing a textual representation of an IPv4 or IPv6 address

    :returns: python str containing a normalized address string
    """
    normalized_ip_address = normalize_ip_address(ip_address.encode('utf-8')).decode('utf-8')
    if normalized_ip_address == "":
        raise ValueError(f'Cannot normalize invalid IP address: {ip_address}')
    return normalized_ip_address


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
    """
    Initialize mercury packet processors to process and analyze network data. Standard usage:

    .. code-block:: python

        import mercury
        from binascii import unhexlify

        libmerc = mercury.Mercury()

        pkt_data = b'52540012...'
        libmerc.get_mercury_json(unhexlify(pkt_data))

    :param do_analysis: Apply mercury's analysis functionality to packets.
    :type do_analysis: bool
    :param resources: Location of mercury-compatible resources file, necessary if `do_analysis` is set to `True`.
    :type resources: bytes
    :param output_tcp_initial_data: Return TCP initial packet data for unrecognized protocols (default=`False`).
    :type output_tcp_initial_data: bool
    :param output_udp_initial_data: Return UDP initial packet data for unrecognized protocols (default=`False`).
    :type output_udp_initial_data: bool
    :param packet_filter_cfg: Specify the protocols that mercury will analyze (default=`all`).
    :type packet_filter_cfg: bytes
    :param metadata_output: Report additional metadata about protocols (default=`True`).
    :type metadata_output: bool
    :param dns_json_output: When processing DNS packets, return a JSON representation as opposed to Base64 Representation (default=`True`).
    :type dns_json_output: bool
    :param certs_json_output: When processing certificates, return a JSON representation as opposed to Base64 Representation (default=`True`).
    :type certs_json_output: bool
    """
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


    cdef int mercury_init(self, unsigned int verbosity=0):
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


    cpdef dict get_mercury_json(self, bytes pkt_data, double ts=0.0):
        """
        Return mercury's JSON representation of a packet.

        :param pkt_data: packet data
        :type pkt_data: bytes
        :param ts: timestamp associated with the packet data (default=0.0)
        :type ts: double
        :return: JSON-encoded packet.
        :rtype: dict
        """
        cdef unsigned char* pkt_data_ref = pkt_data

        cdef char buf[8192]
        memset(buf, 0, 8192)

        # set timestamp
        cdef timespec c_ts
        c_ts.tv_sec  = int(ts)
        c_ts.tv_nsec = int(math.modf(ts)[0]*1e9)

        mercury_packet_processor_write_json(<mercury_packet_processor>self.mpp, buf, 8192, pkt_data_ref, len(pkt_data), &c_ts)

        cdef str json_str = buf.decode('UTF-8')
        if json_str != None:
            try:
                return json.loads(json_str.strip())
            except:
                return None
        else:
            return None


    cpdef dict get_fingerprint(self, bytes pkt_data):
        """
        Return mercury's network protocol fingerprint (NPF) along with metadata.

        :param pkt_data: packet data
        :type pkt_data: bytes
        :return: JSON-encoded network protocol fingerprint information.
        :rtype: dict
        """
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
        """
        Given a packet, apply the mercury classifier and report relevant analysis metadata.

        :param pkt_data: packet data
        :type pkt_data: bytes
        :return: JSON-encoded analysis output
        :rtype: dict
        """
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
        """
        Directly call into mercury analysis functionality by providing all needed data features.

        :param fp_str: mercury-generated network protocol fingerprint
        :type fp_str: str
        :param server_name: The visible, fully qualified domain name, found in the server_name extension
        :type server_name: str
        :param dst_ip: The destination IP address associated with the packet of interest
        :type dst_ip: str
        :param dst_port: The destination port associated with the packet of interest
        :type dst_port: int
        :return: JSON-encoded analysis output
        :rtype: dict
        """
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

    # cpdef dict perform_analysis_with_weights(self, str fp_str, str server_name, str dst_ip, int dst_port, str user_agent,
    #                              long double new_as_weight, long double new_domain_weight,
    #                              long double new_port_weight, long double new_ip_weight,
    #                              long double new_sni_weight, long double new_ua_weight):
    #     """
    #     Directly call into mercury analysis functionality by providing all needed data features. Additionally,
    #     supply custom weights for each data feature.
    #
    #     :param fp_str: mercury-generated network protocol fingerprint
    #     :type fp_str: str
    #     :param server_name: The visible, fully qualified domain name, found in the server_name extension or the HTTP Host field
    #     :type server_name: str
    #     :param dst_ip: The destination IP address associated with the packet of interest
    #     :type dst_ip: str
    #     :param dst_port: The destination port associated with the packet of interest
    #     :type dst_port: int
    #     :param user_agent: If analyzing an HTTP packet, provide the contents of the HTTP User-Agent field
    #     :type user_agent: str
    #     :param new_as_weight: Updated weight for the Autonomous System data feature
    #     :type new_as_weight: long double
    #     :param new_domain_weight: Updated weight for the domain name data feature
    #     :type new_domain_weight: long double
    #     :param new_port_weight: Updated weight for the destination port data feature
    #     :type new_port_weight: long double
    #     :param new_ip_weight: Updated weight for the destination IP address data feature
    #     :type new_ip_weight: long double
    #     :param new_sni_weight: Updated weight for the server_name data feature
    #     :type new_sni_weight: long double
    #     :param new_ua_weight: Updated weight for the User-Agent data feature
    #     :type new_ua_weight: long double
    #     :return: JSON-encoded analysis output
    #     :rtype: dict
    #     """
    #     if not self.do_analysis:
    #         print(f'error: classifier not loaded (is do_analysis set to True?)')
    #         return None
    #
    #     cdef bytes fp_str_b = fp_str.encode()
    #     cdef char* fp_str_c = fp_str_b
    #     cdef bytes server_name_b = server_name.encode()
    #     cdef char* server_name_c = server_name_b
    #     cdef bytes dst_ip_b = dst_ip.encode()
    #     cdef char* dst_ip_c = dst_ip_b
    #     if user_agent == None:
    #         user_agent = 'None'
    #     cdef bytes user_agent_b = user_agent.encode()
    #     cdef char* user_agent_c = user_agent_b
    #     if user_agent == 'None':
    #         user_agent_c = NULL
    #
    #     cdef analysis_result ar = self.clf.perform_analysis_with_weights(fp_str_c, server_name_c, dst_ip_c, dst_port, user_agent_c,
    #                                                 new_as_weight, new_domain_weight, new_port_weight,
    #                                                 new_ip_weight, new_sni_weight, new_ua_weight)
    #
    #     cdef fingerprint_status fp_status_enum = ar.status
    #     fp_status = fp_status_dict[fp_status_enum]
    #
    #     cdef dict result = {}
    #     result['fingerprint_info'] = {}
    #     result['fingerprint_info']['status'] = fp_status
    #     result['analysis'] = {}
    #     result['analysis']['process']   = ar.max_proc.decode('UTF-8')
    #     result['analysis']['score']     = ar.max_score
    #     result['analysis']['malware']   = ar.max_mal
    #     result['analysis']['p_malware'] = ar.malware_prob
    #
    #     return result

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
        """
        Directly call into mercury analysis functionality by providing all needed data features. Additionally,
        supply custom weights for each data feature.

        :param fp_str: mercury-generated network protocol fingerprint
        :type fp_str: str
        :param server_name: The visible, fully qualified domain name, found in the server_name extension or the HTTP Host field
        :type server_name: str
        :param dst_ip: The destination IP address associated with the packet of interest
        :type dst_ip: str
        :param dst_port: The destination port associated with the packet of interest
        :type dst_port: int
        :param user_agent: If analyzing an HTTP packet, provide the contents of the HTTP User-Agent field
        :type user_agent: str
        :return: JSON-encoded analysis output
        :rtype: dict
        """
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


    cpdef dict get_correlation_object(self, bytes pkt_data, double ts=0.0):
        """
        Return JSON representation of a correlation object, which contains data features
        extracted from a packet that can be used to correlate network and/or endpoint observations.

        :param pkt_data: packet data
        :type pkt_data: bytes
        :param ts: timestamp associated with the packet data (default=0.0)
        :type ts: double
        :return: JSON-encoded correlation object.
        :rtype: dict
        """
        cdef unsigned char* pkt_data_ref = pkt_data

        cdef char buf[8192]
        memset(buf, 0, 8192)

        # set timestamp
        cdef timespec c_ts
        c_ts.tv_sec  = int(ts)
        c_ts.tv_nsec = int(math.modf(ts)[0]*1e9)

        mercury_packet_processor_write_json(<mercury_packet_processor>self.mpp, buf, 8192, pkt_data_ref, len(pkt_data), &c_ts)

        cdef str json_str = buf.decode('UTF-8')
        if json_str != None:
            try:
                r = json.loads(json_str.strip())
            except:
                return None
        else:
            return None

        co = {}

        # populate protocol-agnostic features
        if 'src_ip' in r:
            co['src_ip']   = r['src_ip']
        if 'dst_ip' in r:
            co['dst_ip']   = r['dst_ip']
        if 'src_port' in r:
            co['src_port'] = r['src_port']
        if 'dst_port' in r:
            co['dst_port'] = r['dst_port']
        if 'protocol' in r:
            co['protocol'] = r['protocol']
        if 'ip' in r and 'id' in r['ip']:
            co['ip_id']    = r['ip']['id']

        # populate protocol-aware features
        if 'tls' in r and 'client' in r['tls']:
            if 'random' in r['tls']['client']:
                co['tls_random'] = r['tls']['client']['random']
            if 'server_name' in r['tls']['client']:
                co['tls_server_name'] = r['tls']['client']['server_name']
        if 'http' in r and 'request' in r['http']:
            if 'host' in r['http']['request']:
                co['http_host'] = r['http']['request']['host']
            if 'x_forwarded_for' in r['http']['request']:
                co['http_x_forwarded_for'] = r['http']['request']['x_forwarded_for']
        if 'dns' in r and 'query' in r['dns']:
            if 'id' in r['dns']['query']:
                co['dns_id'] = r['dns']['query']['id']
            if 'question' in r['dns']['query']:
                dns_names = ';'.join([x['name'] for x in r['dns']['query']['question'] if 'name' in x])
                if dns_names != '':
                    co['dns_names'] = dns_names

        return co

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


def parse_dns(str b64_dns):
    """
    Return a JSON representation of the Base64 DNS packet.

    :param b64_dns: Base64-encoded DNS packet.
    :type b64_dns: str
    :return: JSON-encoded DNS packet.
    :rtype: dict
    """
    cdef bytes dns_req = b64decode(b64_dns)
    cdef unsigned int len_ = len(dns_req)

    # create reference to dns so that it doesn't get garbage collected
    cdef char* c_string_ref = dns_req

    # use mercury's dns parser to parse the DNS request
    return json.loads(dns_get_json_string(c_string_ref, len_).decode())


def decode_mercury_fdc(str b64_fdc):
    """
    Return a JSON representation of a decoded mercury FDC object.

    :param b64_fdc: Base64-encoded mercury FDC object.
    :type b64_fdc: str
    :return: JSON-encoded mercury decoded FDC.
    :rtype: dict
    """
    cdef bytes fdc_blob = b64decode(b64_fdc)
    cdef unsigned int len_ = len(fdc_blob)

    # create reference to fdc_blob so that it doesn't get garbage collected
    cdef char* c_string_ref = fdc_blob

    # use mercury's FDC decoder to decode the FDC object
    return json.loads(get_json_decoded_fdc(c_string_ref, len_).decode())



# imports from mercury's asn1 parser
cdef extern from "../libmerc/x509.h":
    cdef struct x509_cert:
        void parse(const void *buffer, unsigned int len)
        string get_json_string()
    cdef struct x509_cert_prefix:
        void parse(const void *buffer, unsigned int len)
        string get_hex_string()


def parse_cert(str b64_cert):
    """
    Return a JSON representation of the Base64 certificate.

    :param b64_cert: Base64-encoded certificate.
    :type b64_cert: str
    :return: JSON-encoded certificate.
    :rtype: dict
    """
    cdef bytes cert = b64decode(b64_cert)
    cdef unsigned int len_ = len(cert)
    cdef x509_cert x

    # create reference to cert so that it doesn't get garbage collected
    cdef char* c_string_ref = cert

    # use mercury's asn1 parser to parse certificate data
    x.parse(<const void*>c_string_ref, len_)

    # get JSON string and return JSON object
    return json.loads(x.get_json_string().decode())


def get_cert_prefix(str b64_cert):
    """
    Return a JSON representation of the Base64 certificate prefix.

    :param b64_cert: Base64-encoded certificate.
    :type b64_cert: str
    :return: hex form of certificate prefix
    :rtype: str
    """
    cdef bytes cert = b64decode(b64_cert)
    cdef unsigned int len_ = len(cert)
    cdef x509_cert_prefix x

    # create reference to cert so that it doesn't get garbage collected
    cdef char* c_string_ref = cert

    # use mercury's asn1 parser to parse certificate data
    x.parse(<const void*>c_string_ref, len_)

    # return hex string
    return x.get_hex_string()  # TBD: make it hex


cdef extern from "../libmerc/datum.h":
    cdef struct datum:
        const unsigned char *data
        const unsigned char *data_end


cdef extern from "../libmerc/ech.hpp":
    cdef cppclass ech_config:
        ech_config(datum &)


cdef extern from "json_string.hpp":
    string get_json_string[T](T &, size_t)


cdef class ECHConfig:
    cdef ech_config* ech_obj

    def __init__(self, bytes ech_config_str):
        cdef unsigned int len_ = len(ech_config_str)

        # create reference to ech_config so that it doesn't get garbage collected
        cdef const unsigned char* c_string_ref = ech_config_str

        cdef datum ech_datum = datum(c_string_ref, c_string_ref + len_)
        self.ech_obj = new ech_config(ech_datum)

    def get_json_string(self):
        json_str = get_json_string(dereference(self.ech_obj), 1024).decode()

        return json.loads(json_str)


def parse_ech_config(str b64_ech_config):
    """
    Return a JSON representation of the Base64 Encrypted Client Hello object.

    :param b64_ech_config: Base64-encoded ECH object.
    :type b64_ech_config: str
    :return: JSON-encoded ECH object.
    :rtype: dict
    """
    cdef bytes ech_config = b64decode(b64_ech_config)

    ech_obj = ECHConfig(ech_config)

    return ech_obj.get_json_string()

