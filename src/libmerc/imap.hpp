// imap.hpp
//
// IMAP (Internet Message Access Protocol) parser
// RFC 3501 - https://www.rfc-editor.org/rfc/rfc3501.html
//

#ifndef IMAP_HPP
#define IMAP_HPP

#include "protocol.h"
#include "datum.h"
#include "base64.h"
#include "utf8.hpp"  

namespace imap {

    // Checks if datum starts with a quote
    struct starts_with_quote {
        static bool check(const datum &d) {
            return d.is_not_empty() && d.data[0] == '"';
        }
    };

    // Parser for quoted strings (includes quotes)
    class quoted_string_parser : public datum {
    public:
        quoted_string_parser(datum &d) {
            if (d.is_empty() || d.data[0] != '"') {
                this->set_null();
                d.set_null();
                return;
            }
            this->data = d.data;
            d.skip(1); // skip opening quote
            d.skip_up_to_delim('"');
            if (d.is_not_empty() && d.data[0] == '"') {
                d.skip(1); // skip closing quote
                this->data_end = d.data;
            } else {
                this->set_null();
                d.set_null();
            }
        }
    };

    // Parser for IMAP token up to space or CR (for status/command words)
    class imap_token : public datum {
    public:
        imap_token(datum &d) {
            uint8_t delim = this->parse_up_to_delimiters(d, ' ', '\r');
            if (delim == 0) {
                this->set_null();
                d.set_null();
            }
        }
    };

    // Parser for IMAP argument fields (e.g., username, password etc) that handles both
    // quoted strings ("user@example.com") and unquoted strings (user@example.com) per RFC 3501
    using field = conditional<starts_with_quote, quoted_string_parser, up_to_required_byte<' '>>;

    // Extracts one complete line including \r\n
    struct imap_line : public datum {
        imap_line(datum &d) {
            const uint8_t *line_start = d.data;
            
            up_to_required_byte<'\r'> line_content{d};
            if (!line_content.is_not_empty()) {
                this->set_null();
                d.set_null();
                return;
            }
        
            crlf delimiter{d};
            if (d.is_null()) {
                this->set_null();
                return;
            }
            
            // Set this datum to full line (includes \r\n)
            this->data = line_start;
            this->data_end = d.data;
        }
    };

    // Parser for LOGIN command arguments: <userid> SP <password>
    struct login_arguments {
        field username;
        optional<literal_byte<' '>> sp;
        field password;
        login_arguments(datum &d) : username{d}, sp{d}, password{d} {}

        void write_json(struct json_object &o) const {
            if (username.is_not_empty()) {
                o.print_key_json_string("username", username);
            }
            if (password.is_not_empty()) {
                o.print_key_json_string("password", password);
            }
        }

        bool is_valid() const { return username.is_not_null() && password.is_not_null(); }
    };

    // Generic parser for response data: <status> [SP <additional-data>]
    // Used by both tagged and untagged responses
    struct response_data {
        imap_token status;
        optional<literal_byte<' '>> sp;
        datum additional_data;
        response_data(datum &d) : status{d}, sp{d}, additional_data{d} {}

        void write_json(struct json_object &o, const char *data_key) const {
            if (status.is_not_empty()) {
                o.print_key_json_string("status", status);
            }
            if (additional_data.is_not_empty()) {
                o.print_key_json_string(data_key, additional_data);
            }
        }

        bool is_valid() const { return status.is_not_null(); }
    };

    // Checks if data is valid base64 OR valid UTF-8 text
    static bool is_valid_continuation_data(const datum &d) {
        if (d.is_empty()) {
            return true; 
        }
        
        size_t check_len = d.length() < 30 ? d.length() : 30;
        const uint8_t *start = d.data_end - check_len;
        
        uint8_t base64_buf[256];
        int result = base64::decode(base64_buf, sizeof(base64_buf), start, check_len);
        
        if (result > 0) {
            return true;  // Valid base64
        }
        
        char utf8_buf[512];
        buffer_stream buf{utf8_buf, sizeof(utf8_buf)};
        return utf8_string::write(buf, start, check_len);
    }

    // Parser for server continuation responses: + SP (resp-text / base64) CRLF
    // Used internally by imap_responses multi-line parser
    struct continuation_response {
        literal_byte<'+'> plus;
        literal_byte<' '> sp;  // Space is mandatory per RFC
        up_to_required_byte<'\r'> data;
        crlf delimiter;
        bool isValid;
        continuation_response(datum &d) :
            plus{d},
            sp{d},
            data{d},
            delimiter{d},
            isValid{false}
        {
            mercury_debug("%s: processing IMAP continuation response\n", __func__);
            
            if (d.is_empty()) {
                // If data is empty, it's valid (e.g., "+ \r\n")
                if (data.is_empty()) {
                    isValid = true;
                } else {
                    // If data exists, validate it (last 30 bytes as base64 or UTF-8)
                    isValid = is_valid_continuation_data(data);
                }
            }
        }

        void write_json(struct json_object &record, bool metadata) {
            (void)metadata;
            if (!isValid) {
                return;
            }

            record.print_key_string("type", "continuation");
            if (data.is_not_empty()) {
                record.print_key_json_string("data", data);
            }
        }

        bool is_not_empty() const { return isValid; }
    };

    // Parser for client continuation data: raw data or cancel (*) CRLF
    // Used internally by imap_requests multi-line parser
    struct continuation_request {
        up_to_required_byte<'\r'> data;
        crlf delimiter;
        bool isValid;
        continuation_request(datum &d) :
            data{d},
            delimiter{d},
            // continuation_request can have raw bytes so not possible to validate like continuation_response
            isValid{d.is_empty()}
        {
            mercury_debug("%s: processing IMAP continuation request\n", __func__);
        }

        void write_json(struct json_object &record, bool metadata) {
            (void)metadata;
            if (!isValid) {
                return;
            }

            record.print_key_bool("is_tagged", false);
            record.print_key_string("type", "continuation");
            if (data.is_not_empty()) {
                // Check if it's a cancel command
                if (data.length() == 1 && data.data[0] == '*') {
                    record.print_key_string("action", "cancel");
                } else {
                    record.print_key_json_string("data", data);
                }
            }
        }

        bool is_not_empty() const { return isValid; }
    };

    // Validate if command is a known IMAP command per RFC 3501
    static bool is_valid_imap_command(const datum &cmd) {
        // command-any: Valid in all states
        if (cmd.case_insensitive_match("capability") ||
            cmd.case_insensitive_match("logout") ||
            cmd.case_insensitive_match("noop")) {
            return true;
        }
        
        // command-auth: Valid in Authenticated or Selected state
        if (cmd.case_insensitive_match("append") ||
            cmd.case_insensitive_match("create") ||
            cmd.case_insensitive_match("delete") ||
            cmd.case_insensitive_match("examine") ||
            cmd.case_insensitive_match("list") ||
            cmd.case_insensitive_match("lsub") ||
            cmd.case_insensitive_match("rename") ||
            cmd.case_insensitive_match("select") ||
            cmd.case_insensitive_match("status") ||
            cmd.case_insensitive_match("subscribe") ||
            cmd.case_insensitive_match("unsubscribe")) {
            return true;
        }
        
        // command-nonauth: Valid in Not Authenticated state
        if (cmd.case_insensitive_match("login") ||
            cmd.case_insensitive_match("authenticate") ||
            cmd.case_insensitive_match("starttls")) {
            return true;
        }
        
        // command-select: Valid in Selected state
        if (cmd.case_insensitive_match("check") ||
            cmd.case_insensitive_match("close") ||
            cmd.case_insensitive_match("expunge") ||
            cmd.case_insensitive_match("copy") ||
            cmd.case_insensitive_match("fetch") ||
            cmd.case_insensitive_match("store") ||
            cmd.case_insensitive_match("uid") ||
            cmd.case_insensitive_match("search")) {
            return true;
        }
        
        // IMAP extensions start with 'X' - we'll accept them
        if (cmd.length() > 0 && (cmd.data[0] == 'X' || cmd.data[0] == 'x')) {
            return true;
        }
        
        return false;  // Unknown command
    }

    // IMAP client request parser
    // Parses imap request commands: <tag> SP <command> [SP <arguments>] CRLF
    // Used internally by imap_requests multi-line parser
    struct request {
        up_to_required_byte<' '> tag;           
        literal_byte<' '> sp1;                  
        alphabetic command;
        optional<literal_byte<' '>> sp2;        
        up_to_required_byte<'\r'> arguments;
        crlf delimiter;
        bool isValid;
        request(datum &d) :
            tag{d},
            sp1{d},
            command{d},
            sp2{d},
            arguments{d},
            delimiter{d},
            isValid{tag.is_not_empty() && command.is_not_empty() && d.is_empty()}
        {
            mercury_debug("%s: processing IMAP request packet\n", __func__);
            
            // Validate command is a known IMAP command
            if (isValid && !is_valid_imap_command(command)) {
                mercury_debug("%s: rejecting unknown IMAP command\n", __func__);
                isValid = false;
            }
        }

        void write_json(struct json_object &record, bool metadata) {
            if (!isValid) {
                return;
            }

            bool is_login = command.case_insensitive_match("login");
            bool is_authenticate = command.case_insensitive_match("authenticate");
           
            record.print_key_bool("is_tagged", true);
            record.print_key_json_string("tag", tag);
                       
            record.print_key_json_string("command", command);
            
            if (is_login && arguments.is_not_empty()) {
                // Parsing LOGIN command packet to extract username and password
                datum args_copy{arguments};
                login_arguments login_args{args_copy};
                login_args.write_json(record);
            } else if (is_authenticate && arguments.is_not_empty()) {
                // Parsing AUTHENTICATE command packet to extract auth_type
                record.print_key_json_string("auth_type", arguments);
            } else if (arguments.is_not_empty()) {
                record.print_key_uint("args_length", arguments.length());
                if (metadata) {
                    record.print_key_json_string("arguments", arguments);
                }
            }
        }

        bool is_not_empty() const { return isValid; }
    };

    // IMAP server response parser
    // Parses two formats per RFC 3501:
    // 1. Untagged: * SP <response-data> CRLF
    // 2. Tagged: <tag> SP (OK|NO|BAD) SP <response-text> CRLF
    // Used internally by imap_responses multi-line parser
    struct response {
        up_to_required_byte<' '> tag_or_star;      
        literal_byte<' '> sp1;                      
        up_to_required_byte<'\r'> response_data_field;    
        crlf delimiter;
        bool isValid;
        bool is_untagged;
        response(datum &d) :
            tag_or_star{d},
            sp1{d},
            response_data_field{d},
            delimiter{d},
            isValid{tag_or_star.is_not_empty() && response_data_field.is_not_empty() && d.is_empty()},
            is_untagged{false}
        {
            mercury_debug("%s: processing IMAP response packet\n", __func__);
            
            if (isValid) {
                // Check if this is an untagged response (starts with "*")
                is_untagged = (tag_or_star.length() == 1 && tag_or_star.data[0] == '*');
                
                // Tagged responses MUST start with status code: ok, no, or bad
                if (!is_untagged) {
                    // Extract the status code (first word after tag)
                    datum check_status = response_data_field;
                    imap_token status_code{check_status};
                    
                    if (!status_code.case_insensitive_match("ok") &&
                        !status_code.case_insensitive_match("no") &&
                        !status_code.case_insensitive_match("bad")) {
                        isValid = false;  // Not a valid IMAP tagged response
                    }
                }
                
                if (isValid) {
                    mercury_debug("%s: parsed IMAP %s response\n", __func__, 
                                 is_untagged ? "untagged" : "tagged");
                }
            }
        }

        enum class untagged_type {
            resp_cond_state,  // * OK/NO/BAD
            capability,       // * CAPABILITY
            other_data        // mailbox-data / message-data / other
        };

        // Determine untagged response type from first word
        static untagged_type classify_untagged_response(const imap_token &first_word) {
            if (first_word.case_insensitive_match("ok") ||
                first_word.case_insensitive_match("no") ||
                first_word.case_insensitive_match("bad")) {
                return untagged_type::resp_cond_state;
            }
            if (first_word.case_insensitive_match("capability")) {
                return untagged_type::capability;
            }
            return untagged_type::other_data;
        }

        // Print untagged response based on type
        static void print_untagged_response(struct json_object &imap_response, 
                                           const imap_token &first_word,
                                           datum &data_copy,
                                           const datum &original_data) {
            untagged_type type = classify_untagged_response(first_word);
            switch (type) {
                case untagged_type::resp_cond_state:
                    // resp-cond-state: * (OK|NO|BAD) SP resp-text
                    imap_response.print_key_string("type", "resp-cond-state");
                    imap_response.print_key_json_string("status", first_word);
                    if (data_copy.is_not_empty() && data_copy.data[0] == ' ') {
                        data_copy.skip(1);
                    }
                    if (data_copy.is_not_empty()) {
                        imap_response.print_key_json_string("text", data_copy);
                    }
                    break;
                    
                case untagged_type::capability:
                    // capability-data: * CAPABILITY ...
                    imap_response.print_key_string("type", "capability");
                    if (data_copy.is_not_empty() && data_copy.data[0] == ' ') {
                        data_copy.skip(1);
                    }
                    if (data_copy.is_not_empty()) {
                        imap_response.print_key_json_string("data", data_copy);
                    }
                    break;
                    
                case untagged_type::other_data:
                    // mailbox-data / message-data / other
                    imap_response.print_key_string("type", "data");
                    imap_response.print_key_json_string("data", original_data);
                    break;
            }
        }

        void write_json(struct json_object &record, bool metadata) {
            (void)metadata;
            if (!isValid) {
                return;  
            }

            record.print_key_bool("is_tagged", !is_untagged);
            
            if (is_untagged) {
                datum data_copy = response_data_field;
                imap_token first_word{data_copy};
                print_untagged_response(record, first_word, data_copy, response_data_field);
                
            } else {
                // Tagged response: <tag> SP (OK|NO|BAD) SP <response-text> CRLF
                record.print_key_json_string("tag", tag_or_star);
            
                datum data_copy = response_data_field;
                imap_token status_code{data_copy};
                
                record.print_key_json_string("status", status_code);
            
                if (data_copy.is_not_empty() && data_copy.data[0] == ' ') {
                    data_copy.skip(1);
                }

                if (data_copy.is_not_empty()) {
                    record.print_key_json_string("text", data_copy);
                }
            }
        }

        bool is_not_empty() const { return isValid; }
    };

    // Multi-line IMAP request parser
    class imap_requests : public base_protocol {
        datum requests; 
        bool valid = false;
        bool is_tagged_request = false;
        
    public:
        
        imap_requests(datum &d) : requests(d) {
            parse(d);
        }
        
        // Protocol identification via first-line validation:
        // Valid IMAP requests MUST start with either a tagged request (tag SP command) or
        // a continuation request. If the first line matches either format,
        // the data is IMAP protocol. Subsequent lines (if any) will be parsed during
        // write_json(). This single-line check is sufficient for protocol identification.
        void parse(datum &d) {
            lookahead<imap_line> line_check{d};
            if (!line_check) {
                return;
            }
            
            imap_line line{d};
            
            // Try parsing as normal request (tag + command)
            if (lookahead<request>{line}) {
                datum req_copy = line;
                request req{req_copy};
                if (req.is_not_empty()) {
                    // It's a tagged request (can be multi-line)
                    valid = true;
                    is_tagged_request = true;  
                }
                return;
            }
            
            // Try parsing as continuation request (must be alone per RFC)
            if (lookahead<continuation_request>{line}) {
                datum cont_copy = line;
                continuation_request cont{cont_copy};
                if (cont.is_not_empty() && d.is_empty()) {
                    // It's a continuation request (single line only)
                    valid = true;
                    is_tagged_request = false;  
                }
            }
        }
    
        void write_json(json_object &record, bool metadata) {
            if (!valid) {
                return;
            }
            
            datum temp = requests;
            json_object imap_obj{record, "imap"};
            json_array requests_array{imap_obj, "requests"};
            
            if (is_tagged_request) {
                // Tagged request: can be multi-line
                while (temp.is_not_empty()) {
                
                    lookahead<imap_line> line_check{temp};
                    if (!line_check) {
                        break;
                    }
                    
                    imap_line line{temp};
                    
                    // Parse as normal single line request
                    if (lookahead<request>{line}) {
                        datum req_copy = line;
                        request req{req_copy};
                        if (req.is_not_empty()) {
                            json_object req_obj{requests_array};
                            req.write_json(req_obj, metadata);
                            req_obj.close();
                        }
                    }
                }
            } else {
                // Continuation request: single line only per RFC
                datum cont_copy = temp;
                continuation_request cont{cont_copy};
                json_object cont_obj{requests_array};
                cont.write_json(cont_obj, metadata);
                cont_obj.close();
            }
            
            requests_array.close();
            imap_obj.close();
        }
        
        bool is_not_empty() const { return valid; }
        
        void write_l7_metadata(cbor_object &o, bool) {
            cbor_array protocols{o, "protocols"};
            protocols.print_string("imap");
            protocols.close();
        }
    };

    // Multi-line IMAP response parser
    class imap_responses : public base_protocol {
        datum responses;
        bool valid = false;
        bool is_continuation_response = false;
        
    public:
        
        imap_responses(datum &d) : responses(d) {
            parse(d);
        }
        
        void parse(datum &d) {
            lookahead<imap_line> line_check{d};
            if (!line_check) {
                return;
            }
            
            imap_line line{d};
            
            // Try parsing as continuation response (must be alone per RFC)
            if (lookahead<continuation_response>{line}) {
                datum cont_copy = line;
                continuation_response cont{cont_copy};
                if (cont.is_not_empty() && d.is_empty()) {
                    valid = true;
                    is_continuation_response = true;  // It's a continuation response (single line only)
                }
                return;
            }
            
            // Try parsing as normal response (can be multi-line)
            if (lookahead<response>{line}) {
                datum resp_copy = line;
                response resp{resp_copy};
                if (resp.is_not_empty()) {
                    valid = true;
                    is_continuation_response = false;  // It's a normal response (can be multi-line)
                }
            }
        }
        
        void write_json(json_object &record, bool metadata) {
            if (!valid) {
                return;
            }
            
            datum temp = responses;
            json_object imap_obj{record, "imap"};
            json_array responses_array{imap_obj, "responses"};
            
            if (is_continuation_response) {
                // Continuation response: single line only per RFC (already validated in parse)
                datum cont_copy = temp;
                continuation_response cont{cont_copy};
                json_object cont_obj{responses_array};
                cont.write_json(cont_obj, metadata);
                cont_obj.close();
            } else {
                // Normal response: can be multi-line
                while (temp.is_not_empty()) {
                    lookahead<imap_line> line_check{temp};
                    if (!line_check) {
                        break;
                    }
                    
                    imap_line line{temp};
                    
                    // Parse as normal single-line response
                    if (lookahead<response>{line}) {
                        datum resp_copy = line;
                        response resp{resp_copy};
                        if (resp.is_not_empty()) {
                            json_object resp_obj{responses_array};
                            resp.write_json(resp_obj, metadata);
                            resp_obj.close();
                        }
                    }
                }
            }
            
            responses_array.close();
            imap_obj.close();
        }
        
        bool is_not_empty() const { return valid; }
        
        void write_l7_metadata(cbor_object &o, bool) {
            cbor_array protocols{o, "protocols"};
            protocols.print_string("imap");
            protocols.close();
        }
    };

#ifndef NDEBUG
    static bool unit_test() {
        // ================================================================
        // POSITIVE TEST CASES - Requests
        // ================================================================
        
        // Multi-line IMAP requests
        if (!test_json_output<imap::imap_requests>(
            "a0000 CAPABILITY\r\na0001 LOGIN \"neulingern\" \"password\"\r\na0002 LIST\r\n",
            R"({"imap":{"requests":[{"is_tagged":true,"tag":"a0000","command":"CAPABILITY"},{"is_tagged":true,"tag":"a0001","command":"LOGIN","username":"\"neulingern\"","password":"\"password\""},{"is_tagged":true,"tag":"a0002","command":"LIST"}]}})"
        )) {
            return false;
        }
        
        // Single line request
        if (!test_json_output<imap::imap_requests>(
            "a0001 LOGIN \"neulingern\" \"password\"\r\n",
            R"({"imap":{"requests":[{"is_tagged":true,"tag":"a0001","command":"LOGIN","username":"\"neulingern\"","password":"\"password\""}]}})"
        )) {
            return false;
        }
        
        // UTF-8 in credentials (IMAP4rev2)
        if (!test_json_output<imap::imap_requests>(
            "a001 LOGIN \"用户@example.com\" \"密码123\"\r\n",
            R"({"imap":{"requests":[{"is_tagged":true,"tag":"a001","command":"LOGIN","username":"\"\u7528\u6237@example.com\"","password":"\"\u5bc6\u7801123\""}]}})"
        )) {
            return false;
        }
        
        // ================================================================
        // POSITIVE TEST CASES - Responses
        // ================================================================
        
        // Multi-line responses (mixed tagged/untagged)
        if (!test_json_output<imap::imap_responses>(
            "* CAPABILITY IMAP4 IMAP4rev1 IDLE\r\na0000 OK CAPABILITY completed.\r\n",
            R"({"imap":{"responses":[{"is_tagged":false,"type":"capability","data":"IMAP4 IMAP4rev1 IDLE"},{"is_tagged":true,"tag":"a0000","status":"OK","text":"CAPABILITY completed."}]}})"
        )) {
            return false;
        }
        
        // Single line response
        if (!test_json_output<imap::imap_responses>(
            "a0001 OK LOGIN completed.\r\n",
            R"({"imap":{"responses":[{"is_tagged":true,"tag":"a0001","status":"OK","text":"LOGIN completed."}]}})"
        )) {
            return false;
        }
        
        // New IMAP4rev2 keywords
        if (!test_json_output<imap::imap_responses>(
            "* FLAGS (\\\\Seen \\\\Answered $Forwarded $MDNSent)\r\n",
            "{\"imap\":{\"responses\":[{\"is_tagged\":false,\"type\":\"data\",\"data\":\"FLAGS (\\\\\\\\Seen \\\\\\\\Answered $Forwarded $MDNSent)\"}]}}"
        )) {
            return false;
        }
        
        // ================================================================
        // CONTINUATION RESPONSE VALIDATION TESTS
        // ================================================================
        
        // Valid continuation response with base64 data (AUTHENTICATE)
        if (!test_json_output<imap::imap_responses>(
            "+ YGgGCSqGSIb3EgECAgIAb1kwV6A=\r\n",
            R"({"imap":{"responses":[{"type":"continuation","data":"YGgGCSqGSIb3EgECAgIAb1kwV6A="}]}})"
        )) {
            return false;
        }
        
        // Valid continuation response with UTF-8 text
        if (!test_json_output<imap::imap_responses>(
            "+ Ready for additional command text\r\n",
            R"({"imap":{"responses":[{"type":"continuation","data":"Ready for additional command text"}]}})"
        )) {
            return false;
        }
             
        // Invalid continuation response - invalid data (not base64 or UTF-8)
        if (test_json_output<imap::imap_responses>(
            "+ \xFF\xFE\xFD\xFC\xFB\xFA\r\n",
            ""
        )) {
            return false;
        }
        
        // ================================================================
        // NEGATIVE TEST CASES - Should fail to parse
        // ================================================================
        
        // Multi-line with garbage on both lines - should fail
        if (test_json_output<imap::imap_requests>(
            "\x00\xFF\xFE\x01\x02garbage\r\n\x00\xFF\xFE\x01\x02garbage\r\n",
            ""
        )) {
            return false;
        }
        
        // Missing CRLF terminator - should fail
        if (test_json_output<imap::imap_requests>(
            "a004 CAPABILITY",
            ""
        )) {
            return false;
        }
        
        // Multiple junk lines with invalid commands - should not create empty imap array element
        if (!test_json_output<imap::imap_requests>(
            "junk line one\r\njunk line two\r\n",
            "{}"
        )) {
            return false;
        }
        
        return true;
    }

    static inline bool unit_test_passed = imap::unit_test();
#endif

}; // namespace imap

[[maybe_unused]] inline int imap_requests_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<imap::imap_requests>(data, size);
}

[[maybe_unused]] inline int imap_responses_fuzz_test(const uint8_t *data, size_t size) {
    return json_output_fuzzer<imap::imap_responses>(data, size);
}

#endif // IMAP_HPP
