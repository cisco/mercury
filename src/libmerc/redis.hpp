#ifndef REDIS_HPP
#define REDIS_HPP

#include "protocol.h"
#include "datum.h"
#include "json_object.h"
#include "match.h"
#include <cstdlib>
#include <sstream>

// RESP (Redis Serialization Protocol) parser
// Reference: https://redis.io/docs/latest/develop/reference/protocol-spec/

namespace redis
{

    class response : public base_protocol
    {
    private:
        enum redis_type
        {
            SIMPLE_STRING, // +OK\r\n
            ERROR,         // -Error message\r\n
            INTEGER,       // :1000\r\n
            BULK_STRING    // $7\r\nabc\rdef\r\n
        } type;
        datum parsed_data;
        bool isValid;

        bool parse_simple_string(datum &d)
        {
            literal_byte<'+'> marker{d};
            if (d.is_null())
                return false;

            datum content;
            content.parse_up_to_delim(d, '\r');
            if (content.is_not_empty())
            {
                literal_byte<'\r', '\n'> terminator{d};
                if (!d.is_null())
                {
                    type = SIMPLE_STRING;
                    parsed_data = content;
                    return true;
                }
            }
            return false;
        }

        bool parse_error(datum &d)
        {
            literal_byte<'-'> marker{d};
            if (d.is_null())
                return false;

            datum content;
            content.parse_up_to_delim(d, '\r');
            if (content.is_not_empty())
            {
                literal_byte<'\r', '\n'> terminator{d};
                if (!d.is_null())
                {
                    type = ERROR;
                    parsed_data = content;
                    return true;
                }
            }
            return false;
        }

        bool parse_integer(datum &d)
        {
            literal_byte<':'> marker{d};
            if (d.is_null())
                return false;

            datum content;
            content.parse_up_to_delim(d, '\r');
            if (content.is_not_empty())
            {
                literal_byte<'\r', '\n'> terminator{d};
                if (!d.is_null())
                {
                    type = INTEGER;
                    parsed_data = content;
                    return true;
                }
            }
            return false;
        }

        bool parse_bulk_string(datum &d)
        {
            literal_byte<'$'> marker{d};
            if (d.is_null())
                return false;

            datum length_str;
            length_str.parse_up_to_delim(d, '\r');
            if (!length_str.is_not_empty())
                return false;

            literal_byte<'\r', '\n'> length_term{d};
            if (d.is_null())
                return false;

            std::string len_str{(const char *)length_str.data, length_str.length()};
            int length = std::stoi(len_str);

            type = BULK_STRING;
            if (length == -1)
            {
                parsed_data = datum{nullptr, nullptr};
                return true;
            }

            if (length >= 0 && d.data + length + 2 <= d.data_end) // +2 for \r\n
            {
                parsed_data = datum{d.data, d.data + length};
                d.skip(length);
                literal_byte<'\r', '\n'> content_term{d};
                return !d.is_null();
            }
            else if (length > 0)
            {
                // Bulk string is truncated - need more bytes
                parsed_data = datum{d.data, d.data_end};
                return true; // Accept partial bulk string
            }
            return false;
        }

    public:
        response(datum &d) : type{SIMPLE_STRING}, parsed_data{d.data, d.data}, isValid{false}
        {

            char first_char = *d.data;
            switch (first_char)
            {
            case '+':
                isValid = parse_simple_string(d);
                break;
            case '-':
                isValid = parse_error(d);
                break;
            case ':':
                isValid = parse_integer(d);
                break;
            case '$':
                isValid = parse_bulk_string(d);
                break;
            default:
                isValid = false;
                break;
            }
        }

        bool is_not_empty() const { return isValid; }

        void write_json(struct json_object &record, bool)
        {
            struct json_object redis_object{record, "redis"};
            struct json_object redis_response{redis_object, "response"};

            switch (type)
            {
                case SIMPLE_STRING:
                    redis_response.print_key_string("type", "simple_string");
                    redis_response.print_key_json_string("data", parsed_data);
                    break;
                case ERROR:
                    redis_response.print_key_string("type", "error");
                    redis_response.print_key_json_string("data", parsed_data);
                    break;
                case INTEGER:
                    redis_response.print_key_string("type", "integer");
                    redis_response.print_key_json_string("data", parsed_data);
                    break;
                case BULK_STRING:
                    redis_response.print_key_string("type", "bulk_string");
                    if (parsed_data.is_not_empty())
                    {
                        // Limit to first 100 characters
                        ssize_t max_len = 100;
                        if (parsed_data.length() > max_len)
                        {
                            datum truncated{parsed_data.data, parsed_data.data + max_len};
                            redis_response.print_key_json_string("data", truncated);
                        }
                        else
                        {
                            redis_response.print_key_json_string("data", parsed_data);
                        }
                    }
                    else
                    {
                        redis_response.print_key_string("data", "null");
                    }
                    break;
            }

            redis_response.close();
            redis_object.close();
        }

        void write_l7_metadata(cbor_object &o, bool) {
            cbor_array protocols{o, "protocols"};
            protocols.print_string("redis");
            protocols.close();

            cbor_object redis{o, "redis"};
            cbor_object redis_response{redis, "response"};
            switch (type)
            {
                case SIMPLE_STRING:
                    redis_response.print_key_string("type", "simple_string");
                    redis_response.print_key_string("data", parsed_data);
                    break;
                case ERROR:
                    redis_response.print_key_string("type", "error");
                    redis_response.print_key_string("data", parsed_data);
                    break;
                case INTEGER:
                    redis_response.print_key_string("type", "integer");
                    redis_response.print_key_string("data", parsed_data);
                    break;
                case BULK_STRING:
                    redis_response.print_key_string("type", "bulk_string");
                    if (parsed_data.is_not_empty())
                    {
                        // Limit to first 100 characters
                        ssize_t max_len = 100;
                        if (parsed_data.length() > max_len)
                        {
                            datum truncated{parsed_data.data, parsed_data.data + max_len};
                            redis_response.print_key_string("data", truncated);
                        }
                        else
                        {
                            redis_response.print_key_string("data", parsed_data);
                        }
                    }
                    else
                    {
                        redis_response.print_key_string("data", "null");
                    }
                    break;
            }
            redis_response.close();
            redis.close();
        }
    };

    class request : public base_protocol
    {
    private:
        enum request_type
        {
            ARRAY_COMMAND,
            INLINE_COMMAND
        } type;
        datum command_data;
        datum username_data;
        datum password_data;
        bool is_auth_command;
        bool isValid;

        bool parse_bulk_string_element(datum &d, datum &out)
        {
            literal_byte<'$'> marker{d};
            if (d.is_null())
                return false;

            datum length_str;
            length_str.parse_up_to_delim(d, '\r');
            if (!length_str.is_not_empty())
                return false;

            literal_byte<'\r', '\n'> length_term{d};
            if (d.is_null())
                return false;

            std::string len_str{(const char *)length_str.data, length_str.length()};
            int length = std::stoi(len_str);

            if (length < 0 || d.data + length + 2 > d.data_end) // +2 for \r\n
                return false;

            out = datum{d.data, d.data + length};
            d.skip(length);

            literal_byte<'\r', '\n'> content_term{d};
            return !d.is_null();
        }

        bool parse_array_command(datum &d)
        {
            literal_byte<'*'> marker{d};
            if (d.is_null())
                return false;

            datum length_str;
            length_str.parse_up_to_delim(d, '\r');
            if (!length_str.is_not_empty())
                return false;

            literal_byte<'\r', '\n'> length_term{d};
            if (d.is_null())
                return false;

            std::string len_str{(const char *)length_str.data, length_str.length()};
            int length = std::stoi(len_str);

            if (length <= 0)
                return false;

            type = ARRAY_COMMAND;

            // Parse first element (command)
            if (!parse_bulk_string_element(d, command_data))
                return false;

            // Check if command is AUTH (case-insensitive)
            is_auth_command = (command_data.length() == 4 &&
                               (command_data.data[0] == 'A' || command_data.data[0] == 'a') &&
                               (command_data.data[1] == 'U' || command_data.data[1] == 'u') &&
                               (command_data.data[2] == 'T' || command_data.data[2] == 't') &&
                               (command_data.data[3] == 'H' || command_data.data[3] == 'h'));

            if (is_auth_command)
            {
                // AUTH command: parse username (optional) and password
                // Format: AUTH [username] password
                // If length == 2: AUTH password
                // If length == 3: AUTH username password
                if (length == 2)
                {
                    // Only password
                    if (!parse_bulk_string_element(d, password_data))
                        return false;
                }
                else if (length == 3)
                {
                    // Username and password
                    if (!parse_bulk_string_element(d, username_data))
                        return false;
                    if (!parse_bulk_string_element(d, password_data))
                        return false;
                }
            }

            return true;
        }

        bool parse_inline_command(datum &d)
        {
            // Parse command up to space or CRLF
            command_data.parse_up_to_delimiters(d, ' ', '\r');
            if (!command_data.is_not_empty())
                return false;

            type = INLINE_COMMAND;

            // Check if command is AUTH (case-insensitive)
            is_auth_command = (command_data.length() == 4 &&
                               (command_data.data[0] == 'A' || command_data.data[0] == 'a') &&
                               (command_data.data[1] == 'U' || command_data.data[1] == 'u') &&
                               (command_data.data[2] == 'T' || command_data.data[2] == 't') &&
                               (command_data.data[3] == 'H' || command_data.data[3] == 'h'));

            if (is_auth_command && d.is_readable() && *d.data == ' ')
            {
                d.skip(1);
                // Parse username and password for inline AUTH
                // Format: AUTH [username] password
                datum first_arg;
                first_arg.parse_up_to_delimiters(d, ' ', '\r');

                if (d.is_readable() && *d.data == ' ')
                {
                    // Two arguments: username and password
                    username_data = first_arg;
                    d.skip(1);
                    password_data.parse_up_to_delim(d, '\r');
                }
                else
                {
                    // One argument: password only
                    password_data = first_arg;
                }
            }

            literal_byte<'\r', '\n'> terminator{d};
            return !d.is_null();
        }

    public:
        request(datum &d) : type{ARRAY_COMMAND}, is_auth_command{false}, isValid{false}
        {
            if (d.data >= d.data_end)
            {
                return;
            }

            char first_char = *d.data;
            switch (first_char)
            {
            case '*':
                isValid = parse_array_command(d);
                break;
            default:
                isValid = parse_inline_command(d);
                break;
            }
        }

        bool is_not_empty() const { return isValid; }

        void write_json(struct json_object &record, bool)
        {
            struct json_object redis_object{record, "redis"};
            struct json_object redis_request{redis_object, "request"};

            redis_request.print_key_json_string("command", command_data);

            if (is_auth_command)
            {
                struct json_object auth_object{redis_request, "auth"};

                if (username_data.is_not_empty())
                {
                    auth_object.print_key_json_string("username", username_data);
                }

                if (password_data.is_not_empty())
                {
                    auth_object.print_key_json_string("password", password_data);
                }

                auth_object.close();
            }

            redis_request.close();
            redis_object.close();
        }

        void write_l7_metadata(cbor_object &o, bool) {
            cbor_array protocols{o, "protocols"};
            protocols.print_string("redis");
            protocols.close();

            cbor_object redis{o, "redis"};
            cbor_object redis_request{redis, "request"};
            redis_request.print_key_string("command", command_data);
            if (is_auth_command)
            {
                cbor_object auth_object{redis_request, "auth"};

                if (username_data.is_not_empty())
                {
                    auth_object.print_key_string("username", username_data);
                }

                if (password_data.is_not_empty())
                {
                    auth_object.print_key_string("password", password_data);
                }

                auth_object.close();
            }
            redis_request.close();
            redis.close();
        }
    };

#ifndef NDEBUG
    static bool unit_test()
    {
        // array command parsing
        uint8_t get_command[] = "*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n";
        datum get_datum{get_command, get_command + sizeof(get_command) - 1};
        redis::request get_req{get_datum};
        if (!get_req.is_not_empty())
        {
            return false;
        }

        // inline command parsing
        uint8_t ping_command[] = "PING\r\n";
        datum ping_datum{ping_command, ping_command + sizeof(ping_command) - 1};
        redis::request ping_req{ping_datum};
        if (!ping_req.is_not_empty())
        {
            return false;
        }

        // simple string response
        uint8_t ok_response[] = "+OK\r\n";
        datum ok_datum{ok_response, ok_response + sizeof(ok_response) - 1};
        redis::response ok_resp{ok_datum};
        if (!ok_resp.is_not_empty())
        {
            return false;
        }

        // error response
        uint8_t error_response[] = "-ERR unknown command\r\n";
        datum error_datum{error_response, error_response + sizeof(error_response) - 1};
        redis::response error_resp{error_datum};
        if (!error_resp.is_not_empty())
        {
            return false;
        }

        // integer response
        uint8_t int_response[] = ":1000\r\n";
        datum int_datum{int_response, int_response + sizeof(int_response) - 1};
        redis::response int_resp{int_datum};
        if (!int_resp.is_not_empty())
        {
            return false;
        }

        // bulk string response
        uint8_t bulk_response[] = "$5\r\nhello\r\n";
        datum bulk_datum{bulk_response, bulk_response + sizeof(bulk_response) - 1};
        redis::response bulk_resp{bulk_datum};
        if (!bulk_resp.is_not_empty())
        {
            return false;
        }

        return true;
    }

    static inline bool unit_test_passed = redis::unit_test();
#endif

} // namespace redis

[[maybe_unused]] inline int redis_request_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<redis::request>(data, size);
}

[[maybe_unused]] inline int redis_response_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<redis::response>(data, size);
}

#endif // REDIS_HPP
