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

    class response : public base_protocol{
    private:
        
        enum redis_type{
            SIMPLE_STRING, // +OK\r\n
            ERROR,         // -Error message\r\n
            INTEGER,       // :1000\r\n
            BULK_STRING,    // $7\r\nabc\rdef\r\n
            // ARRAY,         // *2\r\n$3\r\nSET\r\n$3\r\nfoo\r\n
        } type;
        
        datum parsed_data;
        bool isValid;

        bool parse_simple_string(datum &d){
            literal_byte<'+'> marker{d};
            if (d.is_null())
                return false;

            datum content;
            content.parse_up_to_delim(d, '\r');
            if (content.is_not_empty()){
                literal_byte<'\r', '\n'> terminator{d};
                if (!d.is_null()){
                    type = SIMPLE_STRING;
                    parsed_data = content;
                    return true;
                }
            }
            return false;
        }

        bool parse_error(datum &d){
            literal_byte<'-'> marker{d};
            if (d.is_null())
                return false;

            datum content;
            content.parse_up_to_delim(d, '\r');
            if (content.is_not_empty()){
                literal_byte<'\r', '\n'> terminator{d};
                if (!d.is_null()){
                    type = ERROR;
                    parsed_data = content;
                    return true;
                }
            }
            return false;
        }

        bool parse_integer(datum &d){
            literal_byte<':'> marker{d};
            if (d.is_null())
                return false;

            datum content;
            content.parse_up_to_delim(d, '\r');
            if (content.is_not_empty()){
                literal_byte<'\r', '\n'> terminator{d};
                if (!d.is_null()){
                    type = INTEGER;
                    parsed_data = content;
                    return true;
                }
            }
            return false;
        }

        bool parse_bulk_string(datum &d){
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

            // Limit to 10 digits (The string can be of any size, but by default, Redis limits it to 512 MB)
            constexpr ssize_t n = 10;
            if (length_str.length() < 0 || length_str.length() > n) {
                return false;
            }

            char len_str[n + 1];
            std::memcpy(len_str, length_str.data, length_str.length());
            len_str[length_str.length()] = '\0';

            int length = std::atoi(len_str);
            if (length == 0 && (len_str[0] != '0' || len_str[1] != '\0')) {
                return false; 
            }

            type = BULK_STRING;
            if (length == -1){
                parsed_data = datum{nullptr, nullptr};
                return true;
            }

            if (length >= 0 && d.data + length + 2 <= d.data_end){ // +2 for \r\n
                parsed_data = datum{d.data, d.data + length};
                d.skip(length);
                literal_byte<'\r', '\n'> content_term{d};
                return !d.is_null();
            }
            else if (length > 0){
                // Bulk string is truncated - need more bytes
                parsed_data = datum{d.data, d.data_end};
                return true; // Accept partial bulk string
            }
            return false;
        }

        // bool parse_first_packet(const uint8_t *data_start, datum &d){
        //     parsed_data = datum{data_start, d.data};
        //     return true;
        // }

        // Array parsing is disabled for the following reasons:
        // 1. Array responses can be very large and span multiple packets
        // 2. Most valuable data is in the command name and auth details, not array contents
        // 3. Parsing full arrays requires complex state management and recursion handling
        // 4. Memory usage grows with array depth and size
        // bool parse_array(datum &d){
        //     literal_byte<'*'> marker{d};
        //     if (d.is_null())
        //         return false;

        //     datum length_str;
        //     length_str.parse_up_to_delim(d, '\r');
        //     if (!length_str.is_not_empty())
        //         return false;

        //     literal_byte<'\r', '\n'> length_term{d};
        //     if (d.is_null())
        //         return false;

        //     std::string len_str{(const char *)length_str.data, length_str.length()};
        //     int length = std::stoi(len_str);

        //     type = ARRAY;
        //     if (length == -1)
        //     {
        //         parsed_data = datum{nullptr, nullptr};
        //         return true;
        //     }

        //     // Store start position to capture full array data
        //     const uint8_t *array_data_start = d.data;
        //     int elements_parsed = 0;

        //     // Parse array elements (supports nested structures)
        //     // For large arrays that may span multiple packets, we parse the first packet only
        //     for (int i = 0; i < length; i++){
        //         if (d.data >= d.data_end){

        //             // How to calculate the additional bytes needed?
        //             additional_bytes_needed = 1; // non-zero value for truncation marker
        //             break;                       // Accept partial array
        //         }

        //         switch (*d.data){
        //         case '+':
        //         case '-':
        //         case ':':{
        //             d.skip(1);
        //             datum element_content;
        //             element_content.parse_up_to_delim(d, '\r');
        //             if (d.data + 1 < d.data_end && d.data[0] == '\r' && d.data[1] == '\n'){
        //                 d.skip(2);
        //                 elements_parsed++;
        //             }
        //             else{
        //                 additional_bytes_needed = 1; // non-zero value for truncation marker
        //                 break;
        //             }
        //         }
        //         break;
        //         case '$':{
        //             datum temp_d = d;
        //             response temp_resp{temp_d};
        //             if (temp_resp.isValid && temp_resp.type == BULK_STRING){
        //                 d = temp_d;
        //                 elements_parsed++;
        //                 if (temp_resp.additional_bytes_needed){
        //                     // Propagate nested truncation
        //                     additional_bytes_needed = temp_resp.additional_bytes_needed;
        //                     return parse_first_packet(array_data_start, d);
        //                 }
        //             }
        //             else{
        //                 additional_bytes_needed = 1; // non-zero value for truncation marker
        //                 return parse_first_packet(array_data_start, d);
        //             }
        //         }
        //         break;
        //         case '*':{
        //             datum temp_d = d;
        //             response temp_resp{temp_d};
        //             if (temp_resp.isValid && temp_resp.type == ARRAY){
        //                 d = temp_d;
        //                 elements_parsed++;
        //                 if (temp_resp.additional_bytes_needed){
        //                     additional_bytes_needed = temp_resp.additional_bytes_needed;
        //                     return parse_first_packet(array_data_start, d);
        //                 }
        //             }
        //             else{
        //                 additional_bytes_needed = 1;
        //                 return parse_first_packet(array_data_start, d);
        //             }
        //         }    
        //         break;
        //         default:
        //             additional_bytes_needed = 1;
        //             return parse_first_packet(array_data_start, d);
        //         }
        //     }

        //     if (elements_parsed == length){
        //         parsed_data = datum{array_data_start, d.data};
        //         return true;
        //     }

        //     if (additional_bytes_needed > 0){
        //         parsed_data = datum{array_data_start, d.data};
        //         return true;
        //     }

        //     return false;
        // }


    public:

        // size_t additional_bytes_needed = 0;

        response(datum &d) : type{SIMPLE_STRING}, parsed_data{d.data, d.data}, isValid{false}{

            char first_char = *d.data;
            switch (first_char){
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
            // case '*':
            //     isValid = parse_array(d);
            //     break;
            default:
                isValid = false;
                break;
            }
        }

        bool is_not_empty() const { return isValid; }

        void write_json(struct json_object &record, bool){
            struct json_object redis_object{record, "redis"};
            struct json_object redis_response{redis_object, "response"};

            switch (type){
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
                    if (parsed_data.is_not_empty()){
                        // Limit to first 100 characters
                        const size_t max_len = 100;
                        const auto data_len = static_cast<size_t>(parsed_data.length());
                        if (data_len > max_len){
                            datum truncated{parsed_data.data, parsed_data.data + max_len};
                            redis_response.print_key_json_string("data", truncated);
                        }
                        else{
                            redis_response.print_key_json_string("data", parsed_data);
                        }
                    }
                    else{
                        redis_response.print_key_string("data", "null");
                    }
                    break;
                // case ARRAY:
                //     redis_response.print_key_string("type", "array");
                //     if (parsed_data.is_not_empty()){
                //         redis_response.print_key_json_string("data", parsed_data);
                //     }
                //     else{
                //         redis_response.print_key_string("data", "null");
                //     }
                //     break;
            }

            redis_response.close();
            redis_object.close();
        }

        void write_l7_metadata(cbor_object &o, bool) {
            cbor_array protocols{o, "protocols"};
            protocols.print_string("redis");
            protocols.close();
        }
    };

    class request : public base_protocol{
    private:
        enum request_type{
            ARRAY_COMMAND,
            INLINE_COMMAND
        } type;
        datum command_data;
        datum username_data;
        datum password_data;
        bool is_auth_command;
        bool isValid;

        bool parse_bulk_string_element(datum &d, datum &out){
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

            // Limit to 10 digits (The string can be of any size, but by default, Redis limits it to 512 MB)
            constexpr ssize_t n = 10;
            if (length_str.length() < 0 || length_str.length() > n) {
                return false;
            }

            char len_str[n + 1];
            std::memcpy(len_str, length_str.data, length_str.length());
            len_str[length_str.length()] = '\0';

            int length = std::atoi(len_str);
            if (length == 0 && (len_str[0] != '0' || len_str[1] != '\0')) {
                return false; 
            }

            if (length < 0 || d.data + length + 2 > d.data_end) // +2 for \r\n
                return false;

            out = datum{d.data, d.data + length};
            d.skip(length);

            literal_byte<'\r', '\n'> content_term{d};
            return !d.is_null();
        }

        bool parse_array_command(datum &d){
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

            std::string len_str{(const char *)length_str.data, static_cast<size_t>(length_str.length())};
            int length = std::stoi(len_str);

            if (length <= 0)
                return false;

            type = ARRAY_COMMAND;

            // Parse first element (command)
            if (!parse_bulk_string_element(d, command_data))
                return false;

            is_auth_command = (command_data.length() == 4 &&
                               (command_data.data[0] == 'A' || command_data.data[0] == 'a') &&
                               (command_data.data[1] == 'U' || command_data.data[1] == 'u') &&
                               (command_data.data[2] == 'T' || command_data.data[2] == 't') &&
                               (command_data.data[3] == 'H' || command_data.data[3] == 'h'));

            if (is_auth_command){
                // AUTH command: parse username (optional) and password
                // Format: AUTH [username] password
                // If length == 2: AUTH password
                // If length == 3: AUTH username password
                if (length == 2){
                    // Only password
                    if (!parse_bulk_string_element(d, password_data))
                        return false;
                }
                else if (length == 3){
                    // Username and password
                    if (!parse_bulk_string_element(d, username_data))
                        return false;
                    if (!parse_bulk_string_element(d, password_data))
                        return false;
                }
            }

            return true;
        }

        bool parse_inline_command(datum &d){
            // Parse command up to space or CRLF
            command_data.parse_up_to_delimiters(d, ' ', '\r');
            if (!command_data.is_not_empty())
                return false;

            type = INLINE_COMMAND;

            is_auth_command = (command_data.length() == 4 &&
                               (command_data.data[0] == 'A' || command_data.data[0] == 'a') &&
                               (command_data.data[1] == 'U' || command_data.data[1] == 'u') &&
                               (command_data.data[2] == 'T' || command_data.data[2] == 't') &&
                               (command_data.data[3] == 'H' || command_data.data[3] == 'h'));

            if (is_auth_command && d.is_readable() && *d.data == ' '){
                d.skip(1);
                // Parse username and password for inline AUTH
                // Format: AUTH [username] password
                datum first_arg;
                first_arg.parse_up_to_delimiters(d, ' ', '\r');

                if (d.is_readable() && *d.data == ' '){
                    // Two arguments: username and password
                    username_data = first_arg;
                    d.skip(1);
                    password_data.parse_up_to_delim(d, '\r');
                }
                else{
                    // One argument: password only
                    password_data = first_arg;
                }
            }

            literal_byte<'\r', '\n'> terminator{d};
            return !d.is_null();
        }

    public:
        request(datum &d) : type{ARRAY_COMMAND}, is_auth_command{false}, isValid{false}{
            if (d.data >= d.data_end){
                return;
            }

            char first_char = *d.data;
            switch (first_char){
            case '*':
                isValid = parse_array_command(d);
                break;
            default:
                isValid = parse_inline_command(d);
                break;
            }
        }

        bool is_not_empty() const { return isValid; }

        void write_json(struct json_object &record, bool){
            struct json_object redis_object{record, "redis"};
            struct json_object redis_request{redis_object, "request"};

            redis_request.print_key_json_string("command", command_data);

            if (is_auth_command){
                struct json_object auth_object{redis_request, "auth"};

                if (username_data.is_not_empty()){
                    auth_object.print_key_json_string("username", username_data);
                }

                if (password_data.is_not_empty()){
                    auth_object.print_key_json_string("password", password_data);
                }

                auth_object.close();
            }

            redis_request.close();
            redis_object.close();
        }

        void write_l7_metadata(cbor_object &o, bool){
            cbor_array protocols{o, "protocols"};
            protocols.print_string("redis");
            protocols.close();
        }
    };

#ifndef NDEBUG
    static bool unit_test(){
        // array command parsing with JSON validation
        if (!test_json_output<redis::request>(
            "*2\r\n$3\r\nGET\r\n$3\r\nkey\r\n",
            "{\"redis\":{\"request\":{\"command\":\"GET\"}}}")
        ) {
            return false;
        }

        // inline command parsing
        if (!test_json_output<redis::request>(
            "PING\r\n",
            "{\"redis\":{\"request\":{\"command\":\"PING\"}}}")
        ) {
            return false;
        }

        // simple string response with JSON validation
        if (!test_json_output<redis::response>(
            "+OK\r\n",
            "{\"redis\":{\"response\":{\"type\":\"simple_string\",\"data\":\"OK\"}}}")
        ) {
            return false;
        }

        // error response
        if (!test_json_output<redis::response>(
            "-ERR unknown command\r\n",
            "{\"redis\":{\"response\":{\"type\":\"error\",\"data\":\"ERR unknown command\"}}}")
        ) {
            return false;
        }

        // integer response
        if (!test_json_output<redis::response>(
            ":1000\r\n",
            "{\"redis\":{\"response\":{\"type\":\"integer\",\"data\":\"1000\"}}}")
        ) {
            return false;
        }

        // bulk string response with JSON validation
        if (!test_json_output<redis::response>(
            "$5\r\nhello\r\n",
            "{\"redis\":{\"response\":{\"type\":\"bulk_string\",\"data\":\"hello\"}}}")
        ) {
            return false;
        }

        // null bulk string response (value is null)
        if (!test_json_output<redis::response>(
            "$-1\r\n",
            "{\"redis\":{\"response\":{\"type\":\"bulk_string\",\"data\":\"null\"}}}")
        ) {
            return false;
        }

        // empty bulk string response (zero length)
        if (!test_json_output<redis::response>(
            "$0\r\n\r\n",
            "{\"redis\":{\"response\":{\"type\":\"bulk_string\",\"data\":\"\"}}}")
        ) {
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
