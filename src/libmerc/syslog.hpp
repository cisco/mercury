// syslog.hpp
//

#ifndef SYSLOG_HPP
#define SYSLOG_HPP

#include "datum.h"
#include "lex.h"
#include "protocol.h"

class syslog : public base_protocol {
    datum body;

public:

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
            o.print_key_uint("pri", priority);
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

    /// construct a \ref syslog message by parsing the data in the
    /// \ref datum \param d
    ///
    syslog(datum &d) : body{d} { }

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
        syslog.print_key_json_string("body", body);

        syslog.close();
    }

    bool is_not_empty() const {
        return body.is_not_null();
    }

};

[[maybe_unused]] inline int syslog_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<syslog>(data, size);
}

#endif // SYSLOG_HPP
