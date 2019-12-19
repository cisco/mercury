"""
 Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.
 License at https://github.com/cisco/mercury/blob/master/LICENSE
"""

import os
import sys
import socket
from binascii import hexlify, unhexlify
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec

# TLS helper classes
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(os.path.dirname(os.path.abspath(__file__))+'/../')
from pmercury.protocols.protocol import Protocol
from pmercury.utils.tls_utils import *
from pmercury.utils.tls_constants import *


class TLS_Certificate_Full(Protocol):
    def __init__(self):
        self.data_cache = {}


    def get_flow_key(self, data, ip_offset, tcp_offset, ip_type, ip_length):
        src_port = data[tcp_offset:tcp_offset+2]
        dst_port = data[tcp_offset+2:tcp_offset+4]
        if ip_type == 'ipv4':
            o_ = ip_offset+ip_length-8
            src_addr = data[o_:o_+4]
            o_ = ip_offset+ip_length-4
            dst_addr = data[o_:o_+4]
        else:
            o_ = ip_offset+ip_length-32
            src_addr = data[o_:o_+16]
            o_ = ip_offset+ip_length-16
            dst_addr = data[o_:o_+16]
        pr = b'\x06' # currently only support TCP

        return b''.join([src_addr,dst_addr,src_port,dst_port,pr])


    def proto_identify(self, data, offset):
        if (data[offset]   == 22 and
            data[offset+1] ==  3 and
            data[offset+2] <=  3 and
            data[offset+5] == 11):
            return True
        return False


    def proto_identify_sh(self, data, offset):
        if (data[offset]    == 22 and
            data[offset+1]  ==  3 and
            data[offset+2]  <=  3 and
            data[offset+5]  ==  2 and
            data[offset+9]  ==  3 and
            data[offset+10] <=  3):
            return True
        return False


    def fingerprint(self, data, ip_offset, tcp_offset, app_offset, ip_type, ip_length, data_len):
        protocol_type = 'tls_certificate'
        fp_str_ = None
        if app_offset+32 >= data_len:
            return protocol_type, fp_str_, None
        flow_key = self.get_flow_key(data, ip_offset, tcp_offset, ip_type, ip_length)
        data = data[app_offset:]

        sh = False
        if self.proto_identify_sh(data,0):
            data = data[9+int(hexlify(data[6:9]),16):]
            if len(data) == 0:
                return protocol_type, fp_str_, None
            sh = True

        if sh and data[0] == 11:
            self.data_cache[flow_key] = b''
        elif self.proto_identify(data,0):
            data = data[5:]
            self.data_cache[flow_key] = b''
        elif flow_key not in self.data_cache and self.proto_identify(data,0) == False:
            return protocol_type, fp_str_, None
        elif flow_key not in self.data_cache:
            return protocol_type, fp_str_, None

        # keep state to deal with larger packets
        data = self.data_cache[flow_key] + data
        if len(data[7:]) < int(hexlify(data[7:10]),16):
            self.data_cache[flow_key] = data
            return protocol_type, fp_str_, None

        certs = data[7:]
        cert_len = int(hexlify(certs[0:3]),16)

        cert_data = certs[3:3+int(hexlify(certs[0:3]),16)]

        try:
            cert = x509.load_der_x509_certificate(cert_data, default_backend())
        except:
            del self.data_cache[flow_key]
            return protocol_type, fp_str_, None

        # build "fingerprint"
        fp_str_ = b''

        # extract serial number and signature algorithm name
        fp_str_ += b'(' + self.int_2_hex(cert.serial_number) + b')'
        fp_str_ += b'(' + hexlify(bytes(cert.signature_algorithm_oid._name,'utf-8')) + b')'

        # extract issuer information
        fp_str_ += b'('
        for issuer in cert.issuer:
            fp_str_ += b'('
            fp_str_ += b'(' + hexlify(bytes(issuer.oid._name,'utf-8')) + b')'
            fp_str_ += b'(' + hexlify(bytes(issuer._value,'utf-8')) + b')'
            fp_str_ += b')'
        fp_str_ += b')'

        # extract validity
        fp_str_ += b'(' + hexlify(bytes(str(cert.not_valid_before),'utf-8')) + b')'
        fp_str_ += b'(' + hexlify(bytes(str(cert.not_valid_after),'utf-8')) + b')'

        # extract subject information
        fp_str_ += b'('
        for subject in cert.subject:
            fp_str_ += b'('
            fp_str_ += b'(' + hexlify(bytes(subject.oid._name,'utf-8')) + b')'
            fp_str_ += b'(' + hexlify(bytes(subject._value,'utf-8')) + b')'
            fp_str_ += b')'
        fp_str_ += b')'

        # extract public key information
        fp_str_ += b'('
        public_key = cert.public_key()
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            fp_str_ += b'(' + hexlify(b'ECPublicKey') + b')'
            fp_str_ += b'(' + hexlify(self.int_2_hex(public_key.key_size)) + b')'
            fp_str_ += b'(' + hexlify(bytes(public_key.curve.name,'utf-8')) + b')'
        elif isinstance(public_key, rsa.RSAPublicKey):
            fp_str_ += b'(' + hexlify(b'RSAPublicKey') + b')'
            fp_str_ += b'(' + hexlify(self.int_2_hex(public_key.key_size)) + b')'
            public_modulus = '%x' % public_key.public_numbers().n
            public_exponent = '%x' % public_key.public_numbers().e
            fp_str_ += b'(' + hexlify(b'0' * (len(public_modulus) % 2) + bytes(public_modulus,'utf-8')) + b')'
            fp_str_ += b'(' + hexlify(b'0' * (len(public_exponent) % 2) + bytes(public_exponent,'utf-8')) + b')'
        elif isinstance(public_key, dsa.DSAPublicKey):
            fp_str_ += b'(' + hexlify(b'DSAPublicKey') + b')'
            fp_str_ += b'(' + hexlify(public_key.key_size) + b')'
            public_value = '%x' % public_key.public_numbers().public_value
            public_modulus = '%x' % public_key.public_numbers().parameter_numbers().public_modulus
            sub_group_order = '%x' % public_key.public_numbers().parameter_numbers().sub_group_order
            generator = '%x' % public_key.public_numbers().parameter_numbers().generator
            fp_str_ += b'(' + hexlify(b'0' * (len(public_value) % 2) + bytes(public_value,'utf-8')) + b')'
            fp_str_ += b'(' + hexlify(b'0' * (len(public_modulus) % 2) + bytes(public_modulus,'utf-8')) + b')'
            fp_str_ += b'(' + hexlify(b'0' * (len(sub_group_order) % 2) + bytes(sub_group_order,'utf-8')) + b')'
            fp_str_ += b'(' + hexlify(b'0' * (len(generator) % 2) + bytes(generator,'utf-8')) + b')'
        fp_str_ += b')'

        # extract extension information
        fp_str_ += b'('
        try:
            for ext in cert.extensions:
                fp_str_ += b'('
                fp_str_ += b'(' + hexlify(bytes(ext.oid._name,'utf-8')) + b')'
                fp_str_ += b')'
            fp_str_ += b')'
        except:
            fp_str_ += b'error parsing cert extensions)'

        del self.data_cache[flow_key]

        return protocol_type, fp_str_.decode(), None


    def get_human_readable(self, fp_str_):
        lit_fp = eval_fp_str_general(fp_str_)
        fp_h = {}
        fp_h['serial_number'] = lit_fp[0][0]
        fp_h['signature_algorithm'] = unhexlify(lit_fp[1][0]).decode()
        fp_h['issuer'] = {}
        for issuer in lit_fp[2]:
            fp_h['issuer'][unhexlify(issuer[0][0]).decode()] = unhexlify(issuer[1][0]).decode()
        fp_h['validity_not_before'] = unhexlify(lit_fp[3][0]).decode()
        fp_h['validity_not_after'] = unhexlify(lit_fp[4][0]).decode()
        fp_h['subject'] = {}
        for subject in lit_fp[5]:
            fp_h['subject'][unhexlify(subject[0][0]).decode()] = unhexlify(subject[1][0]).decode()

        fp_h['public_key'] = {}
        public_key_type = unhexlify(lit_fp[6][0][0]).decode()
        fp_h['public_key']['type'] = public_key_type
        if public_key_type == b'ECPublicKey':
            fp_h['public_key']['key_size'] = int(unhexlify(lit_fp[6][1][0]),16)
            fp_h['public_key']['curve_name'] = unhexlify(lit_fp[6][2][0]).decode()
        if public_key_type == b'RSAPublicKey':
            fp_h['public_key']['key_size'] = int(unhexlify(lit_fp[6][1][0]),16)
            fp_h['public_key']['public_modulus'] = unhexlify(lit_fp[6][2][0]).decode()
            fp_h['public_key']['public_exponent'] = unhexlify(lit_fp[6][3][0]).decode()
        if public_key_type == b'DSAPublicKey':
            fp_h['public_key']['key_size'] = int(unhexlify(lit_fp[6][1][0]),16)
            fp_h['public_key']['public_value'] = unhexlify(lit_fp[6][2][0]).decode()
            fp_h['public_key']['public_modulus'] = unhexlify(lit_fp[6][3][0]).decode()
            fp_h['public_key']['sub_group_order'] = unhexlify(lit_fp[6][4][0]).decode()
            fp_h['public_key']['generator'] = unhexlify(lit_fp[6][5][0]).decode()

        fp_h['extensions'] = {}
        for ext in lit_fp[7]:
            if len(ext) > 0 and len(ext[0]) > 0:
                try:
                    fp_h['extensions'][unhexlify(ext[0][0]).decode()] = ''#self.parse_certificate_extension(unhexlify(ext[1][0]), unhexlify(ext[0][0]))
                except:
                    fp_h['extensions'][ext[0][0]] = ''

        return fp_h


    def int_2_hex(self, i):
        r = b'%x' % i
        if len(r) % 2 != 0:
            r = b'0' + r
        return r


    def parse_certificate_extension(self, ext_value, name):
        ext_obj = {}

        if name == 'keyUsage':
            ext_obj['digital_signature'] = int(ext_value.digital_signature == True)
            ext_obj['content_commitment'] = int(ext_value.content_commitment == True)
            ext_obj['key_encipherment'] = int(ext_value.key_encipherment == True)
            ext_obj['data_encipherment'] = int(ext_value.data_encipherment == True)
            ext_obj['key_agreement'] = int(ext_value.key_agreement == True)
            ext_obj['key_cert_sign'] = int(ext_value.key_cert_sign == True)
            ext_obj['crl_sign'] = int(ext_value.crl_sign == True)
            if ext_value.key_agreement == True:
                ext_obj['encipher_only'] = int(ext_value.encipher_only == True)
                ext_obj['decipher_only'] = int(ext_value.decipher_only == True)
            else:
                ext_obj['encipher_only'] = 0
                ext_obj['decipher_only'] = 0
        elif name == 'basicConstraints':
            ext_obj['CA'] = int(ext_value.ca == True)
            if ext_value.ca == True:
                if ext_value.path_length == None:
                    ext_obj['path_length'] = 'no_restrictions'
                else:
                    ext_obj['path_length'] = ext_value.path_length
        elif name == 'extendedKeyUsage':
            ext_obj['usages'] = []
            for usage in ext_value:
                ext_obj['usages'].append(usage._name)
        elif name == 'oCSPNoCheck':
            ext_obj['OCSP_NO_CHECK'] = 1
        elif name == 'nameConstraints':
            if ext_value.permitted_subtrees != None:
                ext_obj['permitted_subtrees'] = []
                for subtree in ext_value.permitted_subtrees:
                    ext_obj['permitted_subtrees'].append(subtree.value)
            if ext_value.excluded_subtrees != None:
                ext_obj['excluded_subtrees'] = []
                for subtree in ext_value.excluded_subtrees:
                    ext_obj['excluded_subtrees'].append(subtree.value)
        elif name == 'authorityKeyIdentifier':
            ext_obj['key_identifier'] = ext_value.key_identifier.encode('hex')
            if ext_value.authority_cert_issuer != None:
                ext_obj['authority_cert_issuer'] = []
                for issuer in ext_value.authority_cert_issuer:
                    tmp_obj = {}
                    tmp_obj['type'] = get_name_type(issuer)
                    if tmp_obj['type'] == 'DirectoryName':
                        tmp_obj['value'] = []
                        for n in issuer.value:
                            tmp_obj2 = {}
                            tmp_obj2['oid'] = n.oid.dotted_string
                            tmp_obj2['name'] = n.oid._name
                            tmp_obj2['value'] = n.value
                            tmp_obj['value'].append(tmp_obj2)
                    else:
                        tmp_obj['value'] = str(issuer.value)
                    ext_obj['authority_cert_issuer'].append(tmp_obj)
            if ext_value.authority_cert_serial_number != None:
                ext_obj['authority_cert_serial_number'] = ext_value.authority_cert_serial_number
        elif name == 'subjectKeyIdentifier':
            ext_obj['digest'] = ext_value.digest.encode('hex')
        elif name == 'subjectAltName':
            ext_obj['general_names'] = {}
            for nt in name_types:
                ext_obj['general_names'][name_types[nt]] = []
                for alt_name in ext_value.get_values_for_type(nt):
                    tmp_obj = {}
                    tmp_obj['type'] = name_types[nt]
                    tmp_obj['name'] = alt_name
                    ext_obj['general_names'][name_types[nt]].append(tmp_obj)
        elif name == 'issuerAltName':
            ext_obj['general_names'] = {}
            for nt in name_types:
                ext_obj['general_names'][name_types[nt]] = []
                for alt_name in ext_value.get_values_for_type(nt):
                    tmp_obj = {}
                    tmp_obj['type'] = name_types[nt]
                    tmp_obj['name'] = alt_name
                    ext_obj['general_names'][name_types[nt]].append(tmp_obj)
        elif name == 'precertificateSignedCertificateTimestamps':
            ext_obj['signed_certificate_timestamps'] = []
            for sct in ext_value.scts:
                tmp_obj = {}
                if sct.version == sct.version.v1:
                    tmp_version = 'v1'
                elif sct.version == sct.version.v2:
                    tmp_version = 'v2'
                else:
                    tmp_version = 'unknown'
                tmp_obj['version'] = tmp_version
                tmp_obj['log_id'] = sct.log_id.encode('hex')
                tmp_obj['timestamp'] = str(sct.timestamp)
                if sct.entry_type == sct.entry_type.X509_CERTIFICATE:
                    tmp_obj['entry_type'] = 'x509_certificate'
                elif sct.entry_type == sct.entry_type.PRE_CERTIFICATE:
                    tmp_obj['entry_type'] = 'pre_certificate'
                else:
                    tmp_obj['entry_type'] = 'unknown'
                ext_obj['signed_certificate_timestamps'].append(tmp_obj)
        elif name == 'authorityInfoAccess':
            ext_obj['value'] = []
            for desc in ext_value:
                tmp_obj = {}
                tmp_obj['access_method'] = {}
                tmp_obj['access_method']['oid'] = desc.access_method.dotted_string
                tmp_obj['access_method']['name'] = desc.access_method._name
                tmp_obj['access_location'] = {}
                tmp_obj['access_location']['type'] = get_name_type(desc.access_location)
                if tmp_obj['access_location']['type'] == 'DirectoryName':
                    tmp_obj['access_location']['value'] = []
                    for n in desc.access_location.value:
                        tmp_obj2 = {}
                        tmp_obj2['oid'] = n.oid.dotted_string
                        tmp_obj2['name'] = n.oid._name
                        tmp_obj2['value'] = n.value
                        tmp_obj['access_location']['value'].append(tmp_obj2)
                else:
                    tmp_obj['access_location']['value'] = str(desc.access_location.value)
                ext_obj['value'].append(tmp_obj)
        elif name == 'accessDescription':
            ext_obj['type'] = ext_value.access_method.dotted_str
            ext_obj['name'] = ext_value.access_method._name
            ext_obj['access_location'] = {}
            ext_obj['access_location']['type'] = get_name_type(ext_value.access_location)
            if ext_obj['access_location']['type'] == 'DirectoryName':
                ext_obj['access_location']['value'] = []
                for n in ext_value.access_location.value:
                    tmp_obj2 = {}
                    tmp_obj2['oid'] = n.oid.dotted_string
                    tmp_obj2['name'] = n.oid._name
                    tmp_obj2['value'] = n.value
                    ext_obj['access_location']['value'].append(tmp_obj2)
            else:
                ext_obj['access_location']['value'] = str(ext_value.access_location.value)
        elif name == 'cRLDistributionPoints':
            ext_obj['distribution_points'] = {}
            for dist_point in ext_value:
                if dist_point.full_name != None:
                    ext_obj['distribution_points']['full_names'] = []
                    for n in dist_point.full_name:
                        tmp_obj = {}
                        tmp_obj['type'] = get_name_type(n)
                        if tmp_obj['type'] == 'DirectoryName':
                            tmp_obj['value'] = []
                            for n1 in n.value:
                                tmp_obj2 = {}
                                tmp_obj2['oid'] = n1.oid.dotted_string
                                tmp_obj2['name'] = n1.oid._name
                                tmp_obj2['value'] = n1.value
                                tmp_obj['value'].append(tmp_obj2)
                        else:
                            tmp_obj['value'] = str(n.value)
                        ext_obj['distribution_points']['full_names'].append(tmp_obj)
                elif dist_point.relative_name != None:
                    ext_obj['distribution_points']['relative_name'] = []
                    for n in dist_point.relative_name:
                        tmp_obj = {}
                        tmp_obj['type'] = n.oid.dotted_str
                        tmp_obj['name'] = n.oid._name
                        tmp_obj['value'] = n.value
                        ext_obj['distribution_points']['relative_name'].append(tmp_obj)
                elif dist_point.crl_issuer != None:
                    ext_obj['distribution_points']['crl_issuer'] = []
                    for n in dist_point.crl_issuer:
                        tmp_obj = {}
                        tmp_obj['type'] = get_name_type(n)
                        if tmp_obj['type'] == 'DirectoryName':
                            tmp_obj['value'] = []
                            for n1 in n.value:
                                tmp_obj2 = {}
                                tmp_obj2['oid'] = n1.oid.dotted_string
                                tmp_obj2['name'] = n1.oid._name
                                tmp_obj2['value'] = n1.value
                                tmp_obj['value'].append(tmp_obj2)
                        else:
                            tmp_obj['value'] = str(n.value)
                        ext_obj['distribution_points']['crl_issuer'].append(tmp_obj)
                elif dist_point.reasons != None:
                    ext_obj['distribution_points']['reasons'] = []
                    for n in dist_point.reasons:
                        ext_obj['distribution_points']['reasons'].append(n)
        elif name == 'distributionPoint':
            dist_point = ext_value
            if dist_point.full_name != None:
                ext_obj['full_names'] = []
                for n in dist_point.full_name:
                    tmp_obj = {}
                    tmp_obj['type'] = get_name_type(n)
                    if tmp_obj['type'] == 'DirectoryName':
                        tmp_obj['value'] = []
                        for n1 in n.value:
                            tmp_obj2 = {}
                            tmp_obj2['oid'] = n1.oid.dotted_string
                            tmp_obj2['name'] = n1.oid._name
                            tmp_obj2['value'] = n1.value
                            tmp_obj['value'].append(tmp_obj2)
                    else:
                        tmp_obj['value'] = str(n.value)
                    ext_obj['full_names'].append(tmp_obj)
            elif dist_point.relative_name != None:
                ext_obj['relative_name'] = []
                for n in dist_point.relative_name:
                    tmp_obj = {}
                    tmp_obj['type'] = n.oid.dotted_str
                    tmp_obj['name'] = n.oid._name
                    tmp_obj['value'] = n.value
                    ext_obj['relative_name'].append(tmp_obj)
            elif dist_point.crl_issuer != None:
                ext_obj['crl_issuer'] = []
                for n in dist_point.crl_issuer:
                    tmp_obj = {}
                    tmp_obj['type'] = get_name_type(n)
                    if tmp_obj['type'] == 'DirectoryName':
                        tmp_obj['value'] = []
                        for n1 in n.value:
                            tmp_obj2 = {}
                            tmp_obj2['oid'] = n1.oid.dotted_string
                            tmp_obj2['name'] = n1.oid._name
                            tmp_obj2['value'] = n1.value
                            tmp_obj['value'].append(tmp_obj2)
                    else:
                        tmp_obj['value'] = str(n.value)
                    ext_obj['crl_issuer'].append(tmp_obj)
            elif dist_point.reasons != None:
                ext_obj['reasons'] = []
                for n in dist_point.reasons:
                    ext_obj['reasons'].append(n)
        elif name == 'reasonFlags':
            ext_obj['value'] = []
            for r in ext_value:
                ext_obj['value'].append(r)
        elif name == 'inhibitAnyPolicy':
            ext_obj['type'] = ext_value.oid.dotted_str
            ext_obj['name'] = ext_value.oid._name
            ext_obj['skip_certs'] = ext_value.skip_certs
        elif name == 'policyConstraints':
            ext_obj['type'] = ext_value.oid.dotted_str
            ext_obj['name'] = ext_value.oid._name
            if ext_value.require_explicit_policy != None:
                ext_obj['require_explicit_policy'] = ext_value.require_explicit_policy
            if ext_value.inhibit_policy_mapping != None:
                ext_obj['inhibit_policy_mapping'] = ext_value.inhibit_policy_mapping
        elif name == 'cRLNumber':
            ext_obj['type'] = ext_value.oid.dotted_str
            ext_obj['name'] = ext_value.oid._name
            ext_obj['crl_number'] = ext_value.crl_number
        elif name == 'unrecognizedExtension':
            ext_obj['type'] = ext_value.oid.dotted_str
            ext_obj['name'] = ext_value.oid._name
            ext_obj['value'] = ext_value.value.encode('hex')
        elif name == 'certificatePolicies':
            ext_obj['policies'] = []
            for policy in ext_value:
                tmp_obj = {}
                tmp_obj['oid'] = policy.policy_identifier.dotted_string
                tmp_obj['name'] = policy.policy_identifier._name
                if policy.policy_qualifiers != None:
                    tmp_obj['qualifiers'] = []
                    for qualifier in policy.policy_qualifiers:
                        if type(qualifier) == UserNotice:
                            tmp_obj['qualifiers'].append(qualifier.explicit_text)
                        else:
                            tmp_obj['qualifiers'].append(str(qualifier))
                ext_obj['policies'].append(tmp_obj)
        else:
            ext_obj['value'] = 'OID_NYI'


        return ext_obj
