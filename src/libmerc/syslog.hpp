// syslog.hpp
//

#ifndef SYSLOG_HPP
#define SYSLOG_HPP

#include "datum.h"
#include "lex.h"
#include "protocol.h"


/// returns `true` if the \ref datum \param d is readable and contains
/// no non-ASCII characters in the first `std::min(d.length(), \param
/// num_bytes_to_check bytes), and `false` otherwise
///
inline bool is_ascii(datum d, ssize_t num_bytes_to_check) {
    if (d.is_not_readable()) {
        return false;
    }
    d.trim_to_length(num_bytes_to_check);
    unsigned char acc = 0;
    for (const auto & byte : d) {
        acc |= byte;
    }
    return (acc & 0x80) == 0;
}

class syslog : public base_protocol {
    datum body;
    bool valid;

public:

    /// the number of bytes used in the json representation of data
    /// fields other than the syslog.body; this value is used to check
    /// if truncation is needed in order that the syslog json record
    /// will fit into an output buffer
    ///
    constexpr static ssize_t other_json_length = 280;

    // Following RFC 5424 Section 6.2.1 and RFC 3164 Section 4.1.1:
    //
    //    The PRI part MUST have three, four, or five characters and will be
    //    bound with angle brackets as the first and last characters.  The PRI
    //    part starts with a leading "<" ('less-than' character, %d60),
    //    followed by a number, which is followed by a ">" ('greater-than'
    //    character, %d62).  The number contained within these angle brackets
    //    is known as the Priority value (PRIVAL) and represents both the
    //    Facility and Severity.  The Priority value consists of one, two, or
    //    three decimal integers (ABNF DIGITS) using values of %d48 (for "0")
    //    through %d57 (for "9").

    /// class priority represents the PRI part of a message, which
    /// encodes the facility and the severity
    ///
    class priority {
        literal_byte<'<'> lparen;
        digits number;
        literal_byte<'>'> rparen;
        bool valid;
        uint32_t value = 0;

    public:

        priority(datum &d) :
            lparen{d},
            number{d},
            rparen{d},
            valid{d.is_not_null()}
        {
            if (!valid) {
                return;
            }
            for (const auto & x : number) {
                value *= 10;
                value += (x - '0');
                if (value > 191) {   // note: maxiumum value is 23 * 8 + 7
                    d.set_null();
                }
            }
        }

        bool is_valid() const { return valid; }

        /// returns the numerical priority value
        ///
        unsigned int get_value() const {
            return value;
        }

        void write_json(json_object &o) const {
            unsigned int priority = value;
            o.print_key_string("severity", get_severity_string(get_severity(priority)));
            o.print_key_string("facility", get_facility_string(get_facility(priority)));
        }

        /// returns the numerical severity level associated with the
        /// priority (PRI) value \param priority
        ///
        static unsigned int get_severity(unsigned int priority) { return priority % 8; }

        /// returns the numerical facility level associated with the
        /// priority (PRI) value \param priority
        ///
        static unsigned int get_facility(unsigned int priority) {
            unsigned int severity = priority % 8;
            return (priority - severity) / 8;
        }

        /// returns a short string describing the facility associated
        /// with the numerical facility level \param f
        ///
        /// \note facility levels are defined in RFC 5424 Section 6.2.1.
        ///
        static const char * get_facility_string(unsigned int f) {
            switch(f) {
            case  0: return "kernel messages";
            case  1: return "user-level messages";
            case  2:  return "mail system";
            case  3:  return "system daemons";
            case  4:  return "security/authorization messages";
            case  5:  return "messages generated internally by syslogd";
            case  6:  return "line printer subsystem";
            case  7:  return "network news subsystem";
            case  8:  return "UUCP subsystem";
            case  9:  return "clock daemon";
            case 10:  return "security/authorization messages";
            case 11:  return "FTP daemon";
            case 12:  return "NTP subsystem";
            case 13:  return "log audit";
            case 14:  return "log alert";
            case 15:  return "clock daemon";
            case 16:  return "local use 0";
            case 17:  return "local use 1";
            case 18:  return "local use 2";
            case 19:  return "local use 3";
            case 20:  return "local use 4";
            case 21:  return "local use 5";
            case 22:  return "local use 6";
            case 23:  return "local use 7";
            default:
                ;
            }
            return "UNKNOWN";
        }

        /// returns a short string describing the severity associated
        /// with the numerical severity level \param s
        ///
        /// \note severity levels are defined in RFC 5424 Section 6.2.1.
        ///
        static const char * get_severity_string(unsigned int s) {
            switch(s) {
            case 0: return "emergency";
            case 1: return "alert";
            case 2: return "critical";
            case 3: return "error";
            case 4: return "warning";
            case 5: return "notice";
            case 6: return "informational";
            case 7: return "debug";
            default:
                ;
            }
            return "UNKNOWN";
        }

    };

    // static constexpr uint16_t port = hton<uint16_t>(514);

    /// determines the maximum number of bytes of that are verified to
    /// contain ASCII data when a syslog message is constructed
    ///
    static constexpr ssize_t ascii_check_len = 32;

    /// construct a \ref syslog message by parsing the data in the
    /// \ref datum \param d
    ///
    syslog(datum &d) : body{d} , valid{is_ascii(body, ascii_check_len)} { }

    /// write a json representation of this syslog message to the \ref
    /// json_object \param o
    ///
    /// \note the optional parameter \param metadata is present only
    /// for function signature compatibility with other classes
    ///
    void write_json(json_object &o, bool metadata=false) const {
        (void)metadata;

        json_object syslog{o, "syslog"};

        // if the message starts with PRI, then write out the priority
        // value, facility, and severity
        //
        // note: this operation does not change the value of \ref body
        //
        if (lookahead<priority> p{body}) {
            p.value.write_json(syslog);
        }

        // write the complete message body into a JSON-escaped UTF-8
        // string
        //
        datum truncated{body};
        ssize_t max_message_length = syslog.remaining_output_capacity() - other_json_length;
        if (body.length() > max_message_length) {
            truncated.trim_to_length(max_message_length);
            syslog.print_key_uint("original_length", body.length());
        }
        syslog.print_key_json_string("body", truncated);

        syslog.close();
    }

    /// write a cbor representation of this syslog message to the \ref
    /// cbor_object \param o
    ///
    /// \note the optional parameter \param metadata is present only
    /// for function signature compatibility with other classes
    ///
    void write_l7_metadata(cbor_object &o, bool) {
        if (!valid) {
            return;
        }
        cbor_array protocols{o, "protocols"};
        protocols.print_string("syslog");
        protocols.close();
    }

    bool is_not_empty() const {
        return valid;
    }

    /// runs unit tests on syslog and returns true if all pass, and false otherwise
    ///
    [[maybe_unused]] static bool unit_test() {
        auto make_ascii_buffer_with_non_ascii_byte = [](size_t index) {
            std::array<uint8_t, 100> data{};
            data.fill('A');
            data[index] = 0xff;
            return data;
        };

        uint8_t ascii_data[] = {
            0x3c, 0x31, 0x33, 0x3e, 0x4d, 0x61, 0x79, 0x20,
            0x20, 0x36, 0x20, 0x31, 0x32, 0x3a, 0x30, 0x30,
            0x3a, 0x30, 0x30, 0x20, 0x68, 0x6f, 0x73, 0x74,
            0x20, 0x61, 0x70, 0x70, 0x3a, 0x20, 0x6d, 0x73,
            0x67
        };
        datum ascii{ascii_data, ascii_data + sizeof(ascii_data)};
        syslog ascii_msg{ascii};
        if (!ascii_msg.is_not_empty()) {
            return false;
        }

        auto non_ascii_in_prefix = make_ascii_buffer_with_non_ascii_byte(1);
        datum invalid_prefix{non_ascii_in_prefix};
        syslog invalid_prefix_msg{invalid_prefix};
        if (invalid_prefix_msg.is_not_empty()) {
            return false;
        }

        auto non_ascii_after_prefix = make_ascii_buffer_with_non_ascii_byte(ascii_check_len + 8);
        datum valid_prefix{non_ascii_after_prefix};
        syslog valid_prefix_msg{valid_prefix};
        if (!valid_prefix_msg.is_not_empty()) {
            return false;
        }

        return true;
    }

};

[[maybe_unused]] inline int syslog_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<syslog>(data, size);
}

namespace syslog_unit_test {
#ifndef NDEBUG
    inline bool unit_test() {
        char buffer[1024];

        const char *info_msg = "<14>Test syslog message";
        datum d1{(const uint8_t*)info_msg, (const uint8_t*)info_msg + strlen(info_msg)};
        class syslog s1{d1};
        if (!s1.is_not_empty()) return false;
        {
            buffer_stream buf{buffer, sizeof(buffer)};
            json_object json{&buf};
            s1.write_json(json, false);
            json.close();
            buf.write_char('\0');
            if (!strstr(buffer, "syslog")) return false;
            if (!strstr(buffer, "informational")) return false;
            if (!strstr(buffer, "user-level")) return false;
        }

        const char *err_msg = "<11>Error message";
        datum d2{(const uint8_t*)err_msg, (const uint8_t*)err_msg + strlen(err_msg)};
        class syslog s2{d2};
        if (!s2.is_not_empty()) return false;
        {
            buffer_stream buf{buffer, sizeof(buffer)};
            json_object json{&buf};
            s2.write_json(json, false);
            json.close();
            buf.write_char('\0');
            if (!strstr(buffer, "error")) return false;
        }

        const char *no_pri = "Plain text message";
        datum d3{(const uint8_t*)no_pri, (const uint8_t*)no_pri + strlen(no_pri)};
        class syslog s3{d3};
        if (!s3.is_not_empty()) return false;

        return true;
    }
#endif
} // namespace syslog_unit_test

#endif // SYSLOG_HPP
