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
                if (value > 191) {
                    d.set_null();
                }
            }
        }

        bool is_valid() const { return valid; }

        uint32_t get_value() const {
            return value;
        }

        void write_json(json_object &o) const {
            unsigned int priority = value;
            o.print_key_uint("pri", priority);
            unsigned int severity = priority % 8;
            unsigned int facility = (priority - severity)/8;
            o.print_key_string("severity", get_severity_string(severity));
            o.print_key_string("facility", get_facility_string(facility));
        }

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

    class format {
        literal_byte<'<'> lparen;
        digits pri;
        literal_byte<'>'> rparen;
        datum body;

    public:

        format(datum &d) :
            lparen{d},
            pri{d},
            rparen{d},
            body{d}
        {

        }

        void write_json(json_object &) const {
            //            o.print_key_uint("pri", pri.get_value());
        }

    };

    static constexpr uint16_t port = hton<uint16_t>(514);

    syslog(datum &d) : body{d} { }

    void write_json(json_object &o, bool metadata=false) const {
        (void)metadata;
        json_object syslog{o, "syslog"};

        if (lookahead<priority> p{body}) {
            p.value.write_json(syslog);
        }

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
