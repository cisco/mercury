#ifndef FTP_HPP
#define FTP_HPP

#include "protocol.h"
#include "datum.h"
#include "lex.h"
#include "match.h"

// class up_to_byte : public datum
// {
// public:
//     up_to_byte(datum &d, uint8_t byte)
//     {
//         const uint8_t *location = (const uint8_t *)memchr(d.data, byte, d.length());
//         if (location == nullptr)
//         {
//             data = nullptr;
//             data_end = nullptr;
//             d.set_null();
//         }
//         else if (data_end > data)
//         {
//             data_end = location;
//         }
//         data = d.data;
//     }
// };

class up_to_crlf : public datum
{
public:
    up_to_crlf(datum &d)
    {
        this->parse_up_to_delim(d, '\r');
        optional<literal_byte<'\n'>> lf{d};
    }
};

namespace ftp
{

    // FTP command: Section 5.3.1 - Uppercase ASCII, 3 or 4 characters
    class ftp_command : public one_or_more<ftp_command>
    {
    public:
        inline static bool in_class(uint8_t x)
        {
            return (x >= 'A' && x <= 'Z');
        }
    };

    // USER <SP> <username> <CRLF>
    class request : public base_protocol
    {
        ftp_command command;
        literal_byte<' '> sp;
        up_to_crlf argument;

    public:
        request(datum &d) : command{d}, sp{d}, argument{d} {}

        void write_json(struct json_object &record, bool)
        {
            struct json_object ftp_object{record, "ftp"};
            struct json_object ftp_request{ftp_object, "request"};
            ftp_request.print_key_json_string("command", command);
            ftp_request.print_key_json_string("argument", argument);
            ftp_request.close();
            ftp_object.close();
        }

        bool is_not_empty() const { return command.is_not_empty(); }

        // static constexpr mask_and_value<8> user_matcher{
        //     { 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 },
        //     { 'U', 'S', 'E', 'R', ' ', 0x00, 0x00, 0x00 }
        // };

        // static constexpr mask_and_value<8> pass_matcher{
        //     { 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 },
        //     { 'P', 'A', 'S', 'S', ' ', 0x00, 0x00, 0x00 }
        // };

        // static constexpr mask_and_value<8> retr_matcher{
        //     { 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 },
        //     { 'R', 'E', 'T', 'R', ' ', 0x00, 0x00, 0x00 }
        // };

        // static constexpr mask_and_value<8> stor_matcher{
        //     { 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 },
        //     { 'S', 'T', 'O', 'R', ' ', 0x00, 0x00, 0x00 }
        // };
    };

    // From RFC 959 Section 4.2: Reply format
    class response : public base_protocol
    {
        digits status_code;
        literal_byte<' '> sp;
        up_to_crlf reply_text;

    public:
        response(datum &d) : status_code{d}, sp{d}, reply_text{d} {}

        void write_json(struct json_object &record, bool)
        {
            struct json_object ftp_object{record, "ftp"};
            struct json_object ftp_response{ftp_object, "response"};
            ftp_response.print_key_json_string("status_code", status_code);
            ftp_response.print_key_json_string("reply_text", reply_text);
            ftp_response.close();
            ftp_object.close();
        }

        bool is_not_empty() const { return status_code.is_not_empty(); }

        // static constexpr mask_and_value<4> status_code_matcher
        // {
        //     { 0xff, 0xff, 0xff, 0xff },
        //     { '2',  '2',  '0',  ' ' }  // Detect "220 " pattern
        // };

        // static constexpr mask_and_value<4> status_code_matcher
        // {
        //     // detection of ASCII digits (0x30 to 0x39)
        //     { 0xf0, 0xf0, 0xf0, 0xf0 },  // Masks for detecting digit characters (0-9) followed by space/hyphen
        //     { '0',  '0',  '0',  ' ' }    // Base pattern for a generic FTP status code "000 " or "000-"
        // };
    };

#ifndef NDEBUG
    static bool unit_test()
    {

        // True positive test: valid FTP request for USER command
        // uint8_t user_command_packet[] = {
        //     'U', 'S', 'E', 'R', ' ', 'f', 't', 'p', 'u', 's', 'e', 'r', '\r', '\n'
        // };
        // datum user_command{user_command_packet, user_command_packet + sizeof(user_command_packet)};
        // ftp::request valid_request{user_command};
        // if (!valid_request.is_not_empty()) {
        //     return false;
        // }

        // uint8_t valid_response_packet[] = {
        //     '2', '2', '0', ' ', 'S', 'e', 'r', 'v', 'e', 'r', ' ', 'R', 'e', 'a', 'd', 'y', '\r', '\n'
        // };
        // datum response_datum1{valid_response_packet, valid_response_packet + sizeof(valid_response_packet)};
        // ftp::response valid_response1{response_datum1};
        // if (!valid_response1.is_not_empty()) {
        //     return false;
        // }

        // False positive test: invalid garbage packet for request
        uint8_t garbage_packet[20] = {
            0xff, 0xff, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xaa, 0xbb,
            0xcc, 0xdd, 0xee, 0xff};
        datum garbage{garbage_packet, garbage_packet + sizeof(garbage_packet)};
        ftp::request invalid_request{garbage};
        if (invalid_request.is_not_empty())
        {
            return false;
        }

        // False positive test: invalid garbage response
        ftp::response invalid_response{garbage};
        if (invalid_response.is_not_empty())
        {
            return false;
        }

        return true;
    }

    static inline bool unit_test_passed = ftp::unit_test();

#endif
};

[[maybe_unused]] inline int ftp_request_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<ftp::request>(data, size);
}

[[maybe_unused]] inline int ftp_response_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<ftp::response>(data, size);
}

#endif // FTP_HPP
