// fdc.hpp
//
// fingerprint and destination context encoding and decoding

#ifndef FDC_HPP
#define FDC_HPP

#include "result.h"
#include "cbor.hpp"
#include "fingerprint.h"  // for fingerprint::MAX_FP_STR_LEN
#include "cbor_fingerprint.hpp"

// define types of reassembly or truncation possible in the FDC object.
// Currently has "none", reassembled, "truncated", and "reassembled_truncated"
// With L7 support, there may be a need to specify the truncated elements like "tls_cert"
enum class truncation_status : uint64_t {
    none = 0,
    reassembled = 1,
    truncated = 2,
    reassembled_truncated = 3,
    unknown = 4,
    max = 5
};

static const char* const trunc_str[(uint64_t)truncation_status::max] = {
    "none",
    "reassembled",
    "truncated",
    "reassembled_truncated",
    "unknown"
};

static const char* get_truncation_str(truncation_status status) {
    if ((uint64_t)status < (uint64_t)truncation_status::max) {
        return trunc_str[(uint64_t)status];
    }
    return "unknown";
}

/// represents a fingerprint and destination context
///
class fdc {
    datum fingerprint;
    cbor::text_string user_agent;
    cbor::text_string domain_name;
    cbor::text_string dst_ip_str;
    cbor::uint64 dst_port;
    cbor::uint64 truncation;
    bool valid;

public:

    static constexpr uint64_t fdc_version_one = 1;

    fdc(datum fp,
        const char *ua,
        const char *name,
        const char *d_ip,
        uint16_t d_port,
        truncation_status status) :
        fingerprint{fp},
        user_agent{ua},
        domain_name{name},
        dst_ip_str{d_ip},
        dst_port{d_port},
        truncation{(uint64_t)status},
        valid{
            fingerprint.is_not_null()
            and domain_name.is_valid()
            and dst_ip_str.is_valid()
        }
    { }

    bool is_valid() const { return valid; }

    bool encode(writeable &w) const {
        if (not valid) {
            w.set_null();
            return false;
        }
        cbor::output::map m{w};
        cbor::uint64{fdc_version_one}.write(m);
        cbor::output::array a{m};
        cbor_fingerprint::encode_cbor_fingerprint(fingerprint, a);
        domain_name.write(a);
        dst_ip_str.write(a);
        dst_port.write(a);
        user_agent.write(a);
        truncation.write(a);
        a.close();
        m.close();
        return !w.is_null();
    }

    /// decode an fdc object from \ref datum \param d
    ///
    static bool decode(datum &d,
                       writeable &&fp,
                       writeable &&sn_str,
                       writeable &&dst_ip_str,
                       uint16_t &dst_port,
                       writeable &&ua_str,
                       uint64_t &truncation )
    {
        cbor::map m{d};
        cbor::uint64 fdc_version{d};
        if (!d.is_readable() or fdc_version.value() != fdc_version_one) {
            return false;
        }
        cbor::array a{d};
        cbor_fingerprint::decode_cbor_fingerprint(a, fp);
        fp.copy('\0');
        sn_str << cbor::text_string::decode(a).value() << '\0';
        dst_ip_str << cbor::text_string::decode(a).value() << '\0';
        dst_port = cbor::uint64::decode_max(a, 0xffff).value();
        ua_str << cbor::text_string::decode(a).value() << '\0';

        // truncation is an optional field at the array's end, so we check if it exists
        if (d.is_not_empty() && (lookahead<encoded<uint8_t>>{d}).value != 0xff) {
            truncation = cbor::uint64::decode_max(a, (uint64_t)truncation_status::max).value();
        } else {
            truncation = (uint64_t)truncation_status::unknown;
        }
        a.close();
        m.close();

        return d.is_not_null()
            and !fp.is_null()
            and !ua_str.is_null()
            and !sn_str.is_null()
            and !dst_ip_str.is_null();
    }

    static void decode_version_one(datum &d, struct json_object &record) {
        char fp_str[fingerprint::MAX_FP_STR_LEN];
        char dst_ip_str[MAX_ADDR_STR_LEN];
        char sn_str[MAX_SNI_LEN];
        char ua_str[MAX_USER_AGENT_LEN];
        uint16_t dst_port;
        uint64_t truncation;

        bool ok = fdc::decode(d,
                              writeable{(uint8_t*)fp_str, fingerprint::MAX_FP_STR_LEN},
                              writeable{(uint8_t*)sn_str, MAX_SNI_LEN},
                              writeable{(uint8_t*)dst_ip_str, MAX_ADDR_STR_LEN},
                              dst_port,
                              writeable{(uint8_t*)ua_str, MAX_USER_AGENT_LEN},
                              truncation);
        if (ok) {
            json_object fdc_json(record,"fdc");
            fdc_json.print_key_string("fingerprint", fp_str);
            fdc_json.print_key_json_string("sni", datum{sn_str});
            fdc_json.print_key_json_string("dst_ip_str", datum{dst_ip_str});
            fdc_json.print_key_int("dst_port", dst_port);
            fdc_json.print_key_json_string("user_agent", datum{ua_str});
            fdc_json.print_key_string("truncation", get_truncation_str(((truncation_status)truncation)));
            fdc_json.close();
        }
    }

    // LCOV_EXCL_START
    /// perform unit tests on class fdc, returning `true` if they pass
    /// and `false` otherwise
    ///
    static bool unit_test(FILE *f=nullptr) {

        (void)f; // silence warning about unused paramer

        // construct an fpc_object, then encode it into a writeable
        // buffer
        //
        const char *tls_fp = "tls/1/(0301)(c014c00a00390038c00fc0050035c012c00800160013c00dc003000ac013c00900330032c00ec004002fc011c007c00cc002000500040015001200090014001100080006000300ff)[(0000)(000a00340032000100020003000400050006000700080009000a000b000c000d000e000f0010001100120013001400150016001700180019)(000b000403000102)(0023)]";
        const char *http_fp = "http/(434f4e4e454354)(485454502f312e31)((486f7374)(557365722d4167656e74))";
        static constexpr size_t num_tests = 5;
        fdc fdc_object[num_tests]{
            {
                datum{tls_fp},
                "",
                "npmjs.org",
                "104.16.30.34",
                443,
                truncation_status::none
            },
            {
                datum{http_fp},
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "clientservices.googleapis.com:443",
                "72.163.217.105",
                80,
                truncation_status::none
            },
            {
                datum{tls_fp},
                "",
                "npmjs.org",
                "104.16.30.34",
                443,
                truncation_status::truncated
            },
            {
                datum{http_fp},
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                "clientservices.googleapis.com:443",
                "72.163.217.105",
                80,
                truncation_status::reassembled_truncated
            },
            {
                datum{http_fp},
                "user-agent with utf8: stra\u00DFe \r\n\"",
                "abc.com",
                "72.163.217.105",
                80,
                truncation_status::reassembled_truncated
            },
        };
        for (size_t i = 0; i < num_tests; i++){

            dynamic_buffer output{1024};
            bool encoding_ok = fdc_object[i].encode(output);
            if (encoding_ok == false) {
                return false;
            }
            datum encoded_fdc{output.contents()};

            // decode the data in the buffer to decoded_fdc
            //
            char fp_str[fingerprint::MAX_FP_STR_LEN];
            char dst_ip_str[MAX_ADDR_STR_LEN];
            char sn_str[MAX_SNI_LEN];
            char ua_str[MAX_USER_AGENT_LEN];
            uint16_t dst_port;
            uint64_t truncation;

            bool decoding_ok = fdc::decode(encoded_fdc,
                                           writeable{(uint8_t*)fp_str, fingerprint::MAX_FP_STR_LEN},
                                           writeable{(uint8_t*)sn_str, MAX_SNI_LEN},
                                           writeable{(uint8_t*)dst_ip_str, MAX_ADDR_STR_LEN},
                                           dst_port,
                                           writeable{(uint8_t*)ua_str, MAX_USER_AGENT_LEN},
                                           truncation );
            if (decoding_ok == false) {
                return false;
            }
            fdc decoded_fdc(datum{fp_str},
                            ua_str,
                            sn_str,
                            dst_ip_str,
                            dst_port,
                            (truncation_status)truncation);

            // compare the decoded_fdc to the original one; the test
            // passes only if they are equal
            //
            if (decoded_fdc == fdc_object[i]) {
                ;
            }
            else {
                return false;
            }
        }
        return true;
    }
    // LCOV_EXCL_STOP

private:

    /// compare this \ref fdc object with another, returning `true` if
    /// they are equal, and `false` otherwise
    ///
    bool operator== (fdc &rhs) {
        return fingerprint.cmp(rhs.fingerprint) == 0
            and user_agent.value().cmp(rhs.user_agent.value()) == 0
            and domain_name.value().cmp(rhs.domain_name.value()) == 0
            and dst_ip_str.value().cmp(rhs.dst_ip_str.value()) == 0
            and dst_port.value() == rhs.dst_port.value();
    }

};

#endif // FDC_HPP
