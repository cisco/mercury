#ifndef REDIS_HPP
#define REDIS_HPP

#include <variant>

#include "protocol.h"
#include "datum.h"
#include "json_object.h"
#include "match.h"
#include "decimal_int.hpp"
#include "lex.h"

// RESP (Redis Serialization Protocol) parser
// Reference: https://redis.io/docs/latest/develop/reference/protocol-spec/

namespace redis{

    class simple_string;
    class error;
    class integer;
    class bulk_string;
    class array;

    class simple_string {
        literal_byte<'+'> marker;
        up_to_required_byte<'\r'> parsed_data;
        crlf terminator;
        bool isValid;

    public:
        bool truncated = false;

        simple_string(datum &d) :
            marker{d},
            parsed_data{d},
            terminator{d},
            isValid{!d.is_null() && parsed_data.is_not_empty()}{}

        bool is_not_empty() const { return isValid; }

        void write_json(struct json_object &redis_response) const {
            redis_response.print_key_string("type", "simple_string");
            redis_response.print_key_json_string("data", parsed_data);
        }
    };

    class error {
        literal_byte<'-'> marker;
        up_to_required_byte<'\r'> parsed_data;
        crlf terminator;
        bool isValid;

    public:
        bool truncated = false;

        error(datum &d) :
            marker{d},
            parsed_data{d},
            terminator{d},
            isValid{!d.is_null() && parsed_data.is_not_empty()} {}

        bool is_not_empty() const { return isValid; }

        void write_json(struct json_object &redis_response) const {
            redis_response.print_key_string("type", "error");
            redis_response.print_key_json_string("data", parsed_data);
        }
    };

    class integer {
        literal_byte<':'> marker;
        up_to_required_byte<'\r'> parsed_data;
        crlf terminator;
        bool isValid;

    public:
        bool truncated = false;

        integer(datum &d) :
            marker{d},
            parsed_data{d},
            terminator{d},
            isValid{!d.is_null() && parsed_data.is_not_empty()} {}

        bool is_not_empty() const { return isValid; }

        void write_json(struct json_object &redis_response) const {
            redis_response.print_key_string("type", "integer");
            redis_response.print_key_json_string("data", parsed_data);
        }
    };

    class bulk_string {
        literal_byte<'$'> marker;
        decimal_integer<int32_t> length;
        crlf terminator1;
        datum parsed_data;
        bool isValid;

    public:
        bool truncated = false;

        bulk_string(datum &d) :
            marker{d},
            length{d},
            terminator1{d},
            parsed_data{},
            isValid{false}
        {
            if (d.is_null()) {
                return;
            }
            int len = length.get_value();

            if (len == -1) { // Null bulk string: $-1\r\n
                isValid = true;
                return;
            }

            if (len < 0) {
                return; // Invalid length
            }

            if (d.length() >= len + 2) { //$5\r\nhello\r\n
                parsed_data.parse(d, len);
                crlf terminator2{d};
                isValid = !d.is_null();
            }
            else if (len > 0) { // Truncated: needs reassembly
                truncated = true;
                parsed_data = d;
                isValid = true;
            }
        }

        bool is_not_empty() const { return isValid; }
        const datum& get_data() const { return parsed_data; }

        void write_json(struct json_object &redis_response) const {
            redis_response.print_key_string("type", "bulk_string");

            if (!parsed_data.is_null()) {
                if (parsed_data.is_not_empty()) {
                    // Limit to first 100 characters
                    const size_t max_len = 100;
                    const auto data_len = static_cast<size_t>(parsed_data.length());
                    if (data_len > max_len) {
                        datum temp = parsed_data;
                        datum limited_data;
                        limited_data.parse(temp, max_len);
                        redis_response.print_key_json_string("data", limited_data);
                    }
                    else {
                        redis_response.print_key_json_string("data", parsed_data);
                    }
                }
                else {
                    redis_response.print_key_string("data", "");
                }
            }

            if (truncated) {
                redis_response.print_key_bool("truncated", true);
            }
        }
    };

    class array {
        // Compile-time flag to control array parsing execution
        // Array parsing is disabled by default for the following reasons:
        // 1. Array responses can be very large and span multiple packets
        // 2. Most valuable data is in the command name and auth details, not array contents
        // 3. Parsing full arrays requires complex state management and recursion handling
        // 4. Memory usage grows with array depth and size
        static constexpr bool enable_array_parsing = false;

        literal_byte<'*'> marker;
        decimal_integer<int32_t> length_int;
        crlf terminator;
        datum parsed_data;
        bool isValid;

    public:
        bool truncated = true;

        array(datum &d) :
            marker{d},
            length_int{d},
            terminator{d},
            parsed_data{},
            isValid{false}
        {
            if constexpr (!enable_array_parsing) {
                return;
            }

            if (d.is_null()) {
                return;
            }

            int len = length_int.get_value();

            if (len == -1) { // Null array: *-1\r\n
                isValid = true;
                return;
            }

            datum array_data_start = d;
            int elements_parsed = 0;

            auto handle_element_result = [&](auto &element) -> bool {
                if (!element.is_not_empty() || element.truncated) {
                    // Element parsing failed or element itself is truncated
                    truncated = true;
                    parsed_data = array_data_start;
                    isValid = true;
                    return true;
                }

                elements_parsed++;
                return false;
            };

            for (int i = 0; i < len; i++) {
                if (!d.is_readable()) {
                    truncated = true;
                    break;
                }

                if (lookahead<encoded<uint8_t>> first_byte{d}) {
                    bool early_return = false;

                    switch (first_byte.value) {
                        case '+': {
                            simple_string element{d};
                            early_return = handle_element_result(element);
                            break;
                        }
                        case '-': {
                            error element{d};
                            early_return = handle_element_result(element);
                            break;
                        }
                        case ':': {
                            integer element{d};
                            early_return = handle_element_result(element);
                            break;
                        }
                        case '$': {
                            bulk_string element{d};
                            early_return = handle_element_result(element);
                            break;
                        }
                        case '*': {
                            array element{d};
                            early_return = handle_element_result(element);
                            break;
                        }
                        default:
                            return;
                    }

                    if (early_return) {
                        return;
                    }
                }
            }

            if (elements_parsed == len || truncated) {
                parsed_data = array_data_start;
                isValid = true;
            }
        }

        bool is_not_empty() const { return isValid; }

        void write_json(struct json_object &redis_response) const {
            if constexpr (enable_array_parsing) {
                redis_response.print_key_string("type", "array");
                if (parsed_data.is_not_empty()) {
                    redis_response.print_key_json_string("data", parsed_data);
                }
                if (truncated) {
                    redis_response.print_key_bool("truncated", true);
                }
            }
        }
    };

    template<class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
    template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;

    struct write_redis_json {
        json_object &o;
    public:
        write_redis_json(json_object &json) : o{json} { }

        void operator()(std::monostate &) { }
        template <typename T> void operator()(T &x) { x.write_json(o); }
    };

    class response : public base_protocol{
        std::variant<std::monostate, simple_string, error, integer, bulk_string, array> packet;

    public:
        response(datum &d) {
            // Guard against empty payloads (e.g., ACK packets on port 6379)
            if (!d.is_readable()) {
                packet.emplace<std::monostate>();
                return;
            }

            if (lookahead<encoded<uint8_t>> first_char{d}) {
                switch (first_char.value) {
                    case '+':
                        packet.emplace<simple_string>(d);
                        break;
                    case '-':
                        packet.emplace<error>(d);
                        break;
                    case ':':
                        packet.emplace<integer>(d);
                        break;
                    case '$':
                        packet.emplace<bulk_string>(d);
                        break;
                    case '*':
                        packet.emplace<array>(d);
                        break;
                    default:
                        packet.emplace<std::monostate>();
                        break;
                }
            }
            else {
                packet.emplace<std::monostate>();
            }
        }

        bool is_not_empty() const {
            return std::visit(overloaded {
                [](const std::monostate &) -> bool { return false; },
                [](const auto &r) -> bool { return r.is_not_empty(); }
            }, packet);
        }

        void write_json(struct json_object &record, bool){
            if (this->is_not_empty()) {
                struct json_object redis_object{record, "redis"};
                struct json_object redis_response{redis_object, "response"};
                std::visit(write_redis_json{redis_response}, packet);
                redis_response.close();
                redis_object.close();
            }
        }

        void write_l7_metadata(cbor_object &o, bool) {
            cbor_array protocols{o, "protocols"};
            protocols.print_string("redis");
            protocols.close();
        }
    };

    // RESP array format command: *<count>\r\n$<len>\r\n<data>\r\n...
    class array_command {
        literal_byte<'*'> marker;
        decimal_integer<int> array_length;
        crlf array_term;
        datum command_data;
        datum username_data;
        datum password_data;
        bool is_auth_command;
        bool isValid;

    public:
        array_command(datum &d) :
            marker{d},
            array_length{d},
            array_term{d},
            command_data{},
            username_data{},
            password_data{},
            is_auth_command{false},
            isValid{false}
        {
            if (d.is_null()) {
                return;
            }

            int len = array_length.get_value();
            if (len <= 0) {
                return;
            }

            bulk_string cmd{d};
            if (!cmd.is_not_empty()) {
                return;
            }

            command_data = cmd.get_data();
            if (!command_data.is_alnum()) {
                return;
            }

            is_auth_command = command_data.case_insensitive_match("auth");

            if (is_auth_command) {
                // AUTH command: parse username (optional) and password
                // Format: *2\r\n$4\r\nAUTH\r\n$8\r\npassword\r\n
                //     or: *3\r\n$4\r\nAUTH\r\n$8\r\nusername\r\n$8\r\npassword\r\n
                if (len == 2) {
                    bulk_string pwd{d};
                    if (!pwd.is_not_empty()) {
                        return;
                    }
                    password_data = pwd.get_data();
                }
                else if (len == 3) {
                    bulk_string user{d};
                    if (!user.is_not_empty()) {
                        return;
                    }
                    username_data = user.get_data();

                    bulk_string pwd{d};
                    if (!pwd.is_not_empty()) {
                        return;
                    }
                    password_data = pwd.get_data();
                }
            }
            isValid = true;
        }

        bool is_not_empty() const { return isValid; }

        void write_json(struct json_object &redis_request) const {
            redis_request.print_key_json_string("command", command_data);
            if (is_auth_command) {
                struct json_object auth_object{redis_request, "auth"};
                if (username_data.is_not_empty()) {
                    auth_object.print_key_json_string("username", username_data);
                }
                if (password_data.is_not_empty()) {
                    auth_object.print_key_json_string("password", password_data);
                }
                auth_object.close();
            }
        }
    };

    // Inline text format command: COMMAND arg1 arg2\r\n
    class inline_command {
        datum command_data;
        datum username_data;
        datum password_data;
        bool is_auth_command;
        bool isValid;

    public:
        inline_command(datum &d) :
            command_data{},
            username_data{},
            password_data{},
            is_auth_command{false},
            isValid{false}
        {
            command_data.parse_up_to_delimiters(d, ' ', '\r');
            if (!command_data.is_not_empty() || !command_data.is_alnum())
            {
                return;
            }

            is_auth_command = command_data.case_insensitive_match("auth");

            if (is_auth_command) {
                // Parse AUTH arguments: AUTH [username] password\r\n
                if (lookahead<literal_byte<' '>> space_check{d}) {
                    d.skip(1);
                    password_data.parse_up_to_delimiters(d, ' ', '\r');
                    if (lookahead<literal_byte<' '>> space_check2{d}) {
                        // Two arguments: move first to username, parse second into password
                        username_data = password_data;
                        d.skip(1);
                        password_data.parse_up_to_delim(d, '\r');
                    }
                }
            }
            crlf terminator{d};
            isValid = !d.is_null();
        }

        bool is_not_empty() const { return isValid; }

        void write_json(struct json_object &redis_request) const {
            redis_request.print_key_json_string("command", command_data);
            if (is_auth_command) {
                struct json_object auth_object{redis_request, "auth"};
                if (username_data.is_not_empty()) {
                    auth_object.print_key_json_string("username", username_data);
                }
                if (password_data.is_not_empty()) {
                    auth_object.print_key_json_string("password", password_data);
                }
                auth_object.close();
            }
        }
    };

    struct write_request_json {
        struct json_object &redis_request;

        void operator()(const std::monostate &) const { }
        void operator()(const array_command &r) const { r.write_json(redis_request); }
        void operator()(const inline_command &r) const { r.write_json(redis_request); }
    };

    class request : public base_protocol {
        std::variant<std::monostate, array_command, inline_command> packet;

    public:
        request(datum &d) : packet{std::monostate{}} {
            if (!d.is_readable()) {
                return;
            }

            if (lookahead<encoded<uint8_t>> first_char{d}) {
                switch (first_char.value) {
                    case '*':
                        packet.emplace<array_command>(d);
                        break;
                    default:
                        packet.emplace<inline_command>(d);
                        break;
                }
            }
        }

        bool is_not_empty() const {
            return std::visit(overloaded{
                [](const std::monostate &) { return false; },
                [](const array_command &r) { return r.is_not_empty(); },
                [](const inline_command &r) { return r.is_not_empty(); }
            }, packet);
        }

        void write_json(struct json_object &record, bool) {
            if (this->is_not_empty()) {
                struct json_object redis_object{record, "redis"};
                struct json_object redis_request{redis_object, "request"};
                std::visit(write_request_json{redis_request}, packet);
                redis_request.close();
                redis_object.close();
            }
        }

        void write_l7_metadata(cbor_object &o, bool){
            cbor_array protocols{o, "protocols"};
            protocols.print_string("redis");
            protocols.close();
        }
    };

#ifndef NDEBUG
    static bool unit_test(){

        // Array command: GET key
        if (!test_json_output<redis::request>(
            datum{"*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n"},
            datum{"{\"redis\":{\"request\":{\"command\":\"GET\"}}}"})
        ){
            return false;
        }

        // Inline command: PING
        if (!test_json_output<redis::request>(
            datum{"PING\r\n"},
            datum{"{\"redis\":{\"request\":{\"command\":\"PING\"}}}"})
        ){
            return false;
        }

        // Invalid request: non-ASCII command
        datum get_datum{"0xC30xA0bcrn\0"};
        redis::request invalid_req{get_datum};
        if (invalid_req.is_not_empty()){
            return false;
        }

        if (!test_json_output<redis::response>(
            datum{"+OK\r\n"},
            datum{"{\"redis\":{\"response\":{\"type\":\"simple_string\",\"data\":\"OK\"}}}"})
        ){
            return false;
        }

        // Error response
        if (!test_json_output<redis::response>(
            datum{"-ERR unknown command\r\n"},
            datum{"{\"redis\":{\"response\":{\"type\":\"error\",\"data\":\"ERR unknown command\"}}}"})
        ){
            return false;
        }

        // Integer response
        if (!test_json_output<redis::response>(
            datum{":1000\r\n"},
            datum{"{\"redis\":{\"response\":{\"type\":\"integer\",\"data\":\"1000\"}}}"})
        ){
            return false;
        }

        // Bulk string response
        if (!test_json_output<redis::response>(
            datum{"$5\r\nhello\r\n"},
            datum{"{\"redis\":{\"response\":{\"type\":\"bulk_string\",\"data\":\"hello\"}}}"})
        ){
            return false;
        }

        // Null bulk string (should not have "data" field)
        if(!test_json_output<redis::response>(
            datum{"$-1\r\n"},
            datum{"{\"redis\":{\"response\":{\"type\":\"bulk_string\"}}}"})
        ){
            return false;
        }

        // Empty bulk string response (zero length)
        if (!test_json_output<redis::response>(
            datum{"$0\r\n\r\n"},
            datum{"{\"redis\":{\"response\":{\"type\":\"bulk_string\",\"data\":\"\"}}}"})
        ){
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
