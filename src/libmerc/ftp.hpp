#ifndef FTP_HPP
#define FTP_HPP

#include "protocol.h"
#include "datum.h"
#include "lex.h"
#include "match.h"

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

    // FTP command: Section 5.3.1 - Uppercase/Lowercase ASCII, 3 or 4 characters
    // https://www.rfc-editor.org/rfc/rfc959.html
    // Amended versions of commands are tagged with a trailing "+" as mentioned in
    // https://www.iana.org/assignments/ftp-commands-extensions/ftp-commands-extensions.xhtml

    class ftp_command : public one_or_more<ftp_command>
    {
    public:
        inline static bool in_class(uint8_t x)
        {
            return (x >= 'A' && x <= 'Z') || (x >= 'a' && x <= 'z');
        }
    };

    // USER <SP> <username> <CRLF>
    class request : public base_protocol
    {
        ftp_command command;
        literal_byte<' '> sp;
        up_to_crlf argument;
        bool isValid;

    public:
        request(datum &d) : command{d}, sp{d}, argument{d}, isValid{command.length() >= 3 and command.length() <= 4} {}

        void write_json(struct json_object &record, bool)
        {
            struct json_object ftp_object{record, "ftp"};
            struct json_object ftp_request{ftp_object, "request"};
            ftp_request.print_key_json_string("command", command);
            ftp_request.print_key_json_string("argument", argument);
            ftp_request.close();
            ftp_object.close();
        }

        bool is_not_empty() const { return isValid; }

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
    // single-line response: <status_code> <reply-text>

    // multi-line response:
    //<status_code>-<reply-text>\n
    //...
    //<status_code> <reply-text>\n

    class response : public base_protocol
    {
        digits status_code;
        byte_alternatives<' ', '-'> separator;
        datum reply_text;
        bool isValid;

    public:
        response(datum &d) : status_code{d}, separator{d}, reply_text{d}, isValid{status_code.length() == 3 && reply_text.is_not_null()} {}

        bool is_not_empty() const { return isValid; }

        void write_json(struct json_object &record, bool)
        {
            struct json_object ftp_object{record, "ftp"};
            struct json_object ftp_response{ftp_object, "response"};
            ftp_response.print_key_json_string("status_code", status_code);
            ftp_response.print_key_json_string("reply_text", reply_text);
            ftp_response.close();
            ftp_object.close();
        }
    };

#ifndef NDEBUG
    static bool unit_test()
    {
        // Valid Request
        uint8_t user_command_packet[] = "USER ftpuser\r\n";
        datum user_command{user_command_packet, user_command_packet + sizeof(user_command_packet)};
        ftp::request valid_request{user_command};
        if (!valid_request.is_not_empty())
        {
            return false;
        }

        // Valid Request to check for case insensitive commands
        uint8_t pass_command_packet[] = "pass ftpuser\r\n";
        datum pass_command{pass_command_packet, pass_command_packet + sizeof(pass_command_packet)};
        ftp::request valid_case_insensitive_request{pass_command};
        if (!valid_case_insensitive_request.is_not_empty())
        {
            return false;
        }

        // Valid Single-Line Response
        const uint8_t single_line_response[] = "220 Welcome to FTP Server\r\n";
        datum single_datum{single_line_response, single_line_response + sizeof(single_line_response)};
        ftp::response single_response{single_datum};
        if (!single_response.is_not_empty())
        {
            return false;
        }

        // Valid Multi-Line Response
        const uint8_t multi_line_response[] = "230-User logged in.\r\n"
                                              "230 Proceed with file transfer.\r\n";
        datum multi_datum{multi_line_response, multi_line_response + sizeof(multi_line_response)};
        ftp::response multi_response{multi_datum};
        if (!multi_response.is_not_empty())
        {
            return false;
        }

        //  Valid Multi-Line Response with Embedded Status Codes
        const uint8_t multi_with_numbers[] = "123-First line\r\n"
                                             "456 Second line with numbers\r\n"
                                             "123 Last line\r\n";
        datum multi_num_datum{multi_with_numbers, multi_with_numbers + sizeof(multi_with_numbers)};
        ftp::response multi_num_response{multi_num_datum};
        if (!multi_num_response.is_not_empty())
        {
            return false;
        }

        // Valid Request: NOOP command (no argument)
        uint8_t noop_command_packet[] = "NOOP\r\n";
        datum noop_command{noop_command_packet, noop_command_packet + sizeof(noop_command_packet)};
        ftp::request valid_noop_request{noop_command};
        if (!valid_noop_request.is_not_empty())
        {
            return false;
        }

        // Valid Request: STAT command (with argument)
        uint8_t stat_with_arg_command_packet[] = "STAT /home/user\r\n";
        datum stat_with_arg_command{stat_with_arg_command_packet, stat_with_arg_command_packet + sizeof(stat_with_arg_command_packet)};
        ftp::request valid_stat_with_arg_request{stat_with_arg_command};
        if (!valid_stat_with_arg_request.is_not_empty())
        {
            return false;
        }

        uint8_t req_wrong_command_packet[] = "B ftpuser\r\n";
        datum req_wrong_command{req_wrong_command_packet, req_wrong_command_packet + sizeof(req_wrong_command_packet)};
        ftp::request wrong_command{req_wrong_command};
        if (wrong_command.is_not_empty())
        {
            return false;
        }

        // False positive test: invalid garbage response
        const uint8_t invalid_response[] = "XYZ This is not a valid FTP response\r\n";
        datum invalid_datum{invalid_response, invalid_response + sizeof(invalid_response)};
        ftp::response invalid_resp{invalid_datum};
        if (invalid_resp.is_not_empty())
        {
            return false;
        }

        const uint8_t wrong_single_line_response[] = "20 Welcome to FTP Server\r\n";
        datum wrong_single_datum{wrong_single_line_response, wrong_single_line_response + sizeof(wrong_single_line_response)};
        ftp::response wrong_single_response{wrong_single_datum};
        if (wrong_single_response.is_not_empty())
        {
            return false;
        }

        return true;
    }

    static inline bool unit_test_passed = ftp::unit_test();

#endif
};

#endif // FTP_HPP
