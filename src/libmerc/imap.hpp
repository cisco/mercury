// imap.hpp
//
// IMAP (Internet Message Access Protocol) parser
// RFC 3501 - https://www.rfc-editor.org/rfc/rfc3501.html
//

#ifndef IMAP_HPP
#define IMAP_HPP

#include "protocol.h"
#include "datum.h"
#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include <string>  

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

    // Parser for server continuation responses: + [base64-data] CRLF
    // Used internally by imap_responses multi-line parser
    struct continuation_response {
        literal_byte<'+'> plus;
        optional<literal_byte<' '>> sp;
        up_to_required_byte<'\r'> data;
        crlf delimiter;
        bool isValid;
        continuation_response(datum &d) :
            plus{d},
            sp{d},
            data{d},
            delimiter{d},
            isValid{data.is_not_empty() && d.is_empty()}
        {
            mercury_debug("%s: processing IMAP continuation response\n", __func__);
        }

        void write_json(struct json_object &record, bool metadata) {
            (void)metadata;
            if (!isValid) {
                return;
            }

            struct json_object imap_response{record, "response"};
            imap_response.print_key_string("type", "continuation");
            if (data.is_not_empty()) {
                imap_response.print_key_json_string("data", data);
            }
            imap_response.close();
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
            isValid{d.is_empty()}
        {
            mercury_debug("%s: processing IMAP continuation request\n", __func__);
        }

        void write_json(struct json_object &record, bool metadata) {
            (void)metadata;
            if (!isValid) {
                return;
            }

            struct json_object imap_request{record, "request"};
            imap_request.print_key_bool("is_tagged", false);
            imap_request.print_key_string("type", "continuation");
            if (data.is_not_empty()) {
                // Check if it's a cancel command
                if (data.length() == 1 && data.data[0] == '*') {
                    imap_request.print_key_string("action", "cancel");
                } else {
                    imap_request.print_key_json_string("data", data);
                }
            }
            imap_request.close();
        }

        bool is_not_empty() const { return isValid; }
    };

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
        }

        void write_json(struct json_object &record, bool metadata) {
            if (!isValid) {
                return;
            }

            bool is_login = command.case_insensitive_match("login");
            bool is_authenticate = command.case_insensitive_match("authenticate");
           
            struct json_object imap_request{record, "request"};
            
            imap_request.print_key_bool("is_tagged", true);
            imap_request.print_key_json_string("tag", tag);
                       
            imap_request.print_key_json_string("command", command);
            
            if (is_login && arguments.is_not_empty()) {
                // Parsing LOGIN command packet to extract username and password
                datum args_copy{arguments};
                login_arguments login_args{args_copy};
                login_args.write_json(imap_request);
            } else if (is_authenticate && arguments.is_not_empty()) {
                // Parsing AUTHENTICATE command packet to extract auth_type
                imap_request.print_key_json_string("auth_type", arguments);
            } else if (arguments.is_not_empty()) {
                imap_request.print_key_uint("args_length", arguments.length());
                if (metadata) {
                    imap_request.print_key_json_string("arguments", arguments);
                }
            }
            
            imap_request.close();
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

        void write_json(struct json_object &record, bool metadata) {
            (void)metadata;
            if (!isValid) {
                return;  
            }

            struct json_object imap_response{record, "response"};
            imap_response.print_key_bool("is_tagged", !is_untagged);
            
            if (is_untagged) {
                // Untagged response: differentiate types based on first word
                datum data_copy = response_data_field;
                imap_token first_word{data_copy};
                
                if (first_word.case_insensitive_match("ok") ||
                    first_word.case_insensitive_match("no") ||
                    first_word.case_insensitive_match("bad")) {
                    // resp-cond-state: * (OK|NO|BAD) SP resp-text
                    imap_response.print_key_string("type", "resp-cond-state");
                    imap_response.print_key_json_string("status", first_word);
                
                    if (data_copy.is_not_empty() && data_copy.data[0] == ' ') {
                        data_copy.skip(1);
                    }

                    if (data_copy.is_not_empty()) {
                        imap_response.print_key_json_string("text", data_copy);
                    }
                    
                } else if (first_word.case_insensitive_match("capability")) {
                    // capability-data: * CAPABILITY ...
                    imap_response.print_key_string("type", "capability");
                    
                    if (data_copy.is_not_empty() && data_copy.data[0] == ' ') {
                        data_copy.skip(1);
                    }
                    if (data_copy.is_not_empty()) {
                        imap_response.print_key_json_string("data", data_copy);
                    }
                    
                } else {
                    // mailbox-data / message-data / other
                    imap_response.print_key_string("type", "data");
                    imap_response.print_key_json_string("data", response_data_field);
                }
                
            } else {
                // Tagged response: <tag> SP (OK|NO|BAD) SP <response-text> CRLF
                imap_response.print_key_json_string("tag", tag_or_star);
            
                datum data_copy = response_data_field;
                imap_token status_code{data_copy};
                
                imap_response.print_key_json_string("status", status_code);
            
                if (data_copy.is_not_empty() && data_copy.data[0] == ' ') {
                    data_copy.skip(1);
                }

                if (data_copy.is_not_empty()) {
                    imap_response.print_key_json_string("text", data_copy);
                }
            }
            
            imap_response.close();
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
            json_array requests_array{record, "imap"};
            
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
            json_array responses_array{record, "imap"};
            
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
        }
        
        bool is_not_empty() const { return valid; }
        
        void write_l7_metadata(cbor_object &o, bool) {
            cbor_array protocols{o, "protocols"};
            protocols.print_string("imap");
            protocols.close();
        }
    };

#ifndef NDEBUG
    
    struct test_case {
        const char *name;
        const char *input;
        const char *expected_json;  // Only used for positive tests
        bool is_request;  // true for requests, false for responses
        bool is_negative;  // true for negative tests
    };
    
    // Compare actual JSON output against expected JSON using RapidJSON
    static bool validate_json(const char *test_name, 
                             const std::string &actual_json,
                             const std::string &expected_json,
                             FILE *output = nullptr) {
        (void)test_name;
        rapidjson::Document actual_doc;
        rapidjson::Document expected_doc;
        
        expected_doc.Parse(expected_json.c_str());
        
        // Check for parse errors in expected
        if (expected_doc.HasParseError()) {
            if (output) {
                fprintf(output, "  ERROR: Expected JSON Parse Error: %s (offset %zu)\n",
                       rapidjson::GetParseError_En(expected_doc.GetParseError()),
                       expected_doc.GetErrorOffset());
            }
            return false;
        }
        
        actual_doc.Parse(actual_json.c_str());
        
        // Check for parse errors in actual
        if (actual_doc.HasParseError()) {
            if (output) {
                fprintf(output, "  ERROR: Actual JSON Parse Error: %s (offset %zu)\n",
                       rapidjson::GetParseError_En(actual_doc.GetParseError()),
                       actual_doc.GetErrorOffset());
            }
            return false;
        }
        
        if (output) {
            fprintf(output, "  Expected: %s\n", expected_json.c_str());
            fprintf(output, "  Actual:   %s\n", actual_json.c_str());
        }
        
        // Compare the two JSON documents
        if (actual_doc == expected_doc) {
            if (output) {
                fprintf(output, "  JSONs are equal\n");
            }
            return true;
        } else {
            if (output) {
                fprintf(output, "  JSONs are not equal\n");
            }
            return false;
        }
    }

    // Helper function to run a single test case
    static bool run_test_case(const test_case &tc, int test_num, FILE *output = nullptr) {
        if (output) fprintf(output, "[Test %d] %s\n", test_num, tc.name);
        if (output) fprintf(output, "  Input: %s\n", tc.input);
        
        datum data{tc.input};
        char buf[4096];
        struct buffer_stream stream(buf, sizeof(buf));
        struct json_object json_obj(&stream);
        
        bool parsed = false;
        if (tc.is_request) {
            imap::imap_requests reqs{data};
            if (reqs.is_not_empty()) {
                reqs.write_json(json_obj, false);
                parsed = true;
            }
        } else {
            imap::imap_responses resps{data};
            if (resps.is_not_empty()) {
                resps.write_json(json_obj, false);
                parsed = true;
            }
        }
        
        // Handle negative test cases
        if (tc.is_negative) {
            if (!parsed) {
                if (output) fprintf(output, "  Result: Parser CORRECTLY rejected invalid input\n");
                if (output) fprintf(output, "PASS [Test %d] - Negative test passed\n\n", test_num);
                return true;  // PASS - rejected as expected
            } else {
                if (output) {
                    fprintf(output, "  ERROR: Parser SHOULD have rejected this invalid input!\n");
                    json_obj.close();
                    std::string json_out(buf, stream.length());
                    fprintf(output, "  Parser output: %s\n", json_out.c_str());
                    fprintf(output, "FAIL [Test %d] - Negative test FAILED (parser too lenient)\n\n", test_num);
                }
                return false;  // FAIL - should have rejected
            }
        }
        
        // Handle positive test cases
        if (!parsed) {
            if (output) fprintf(output, "  ERROR: Parsing failed!\n");
            if (output) fprintf(output, "FAIL [Test %d]\n\n", test_num);
            return false;
        }
        
        if (output) fprintf(output, "  Parsing: SUCCESS\n");
        json_obj.close();
        std::string json_out(buf, stream.length());
        
        if (!validate_json(tc.name, json_out, tc.expected_json, output)) {
            if (output) fprintf(output, "FAIL [Test %d]\n\n", test_num);
            return false;
        }
        
        if (output) fprintf(output, "  JSON validation: SUCCESS\n");
        if (output) fprintf(output, "PASS [Test %d]\n\n", test_num);
        return true;
    }
    
    static bool unit_test(FILE *output = nullptr) {    
        test_case all_tests[] = {
            // ================================================================
            // POSITIVE TEST CASES (Tests 1-4)
            // ================================================================
            
            // Test 1: Multi-line IMAP requests
            {
                "Multi-line IMAP requests",
                "a0000 CAPABILITY\r\na0001 LOGIN \"neulingern\" \"password\"\r\na0002 LIST\r\n",
                R"({"imap":[{"request":{"is_tagged":true,"tag":"a0000","command":"CAPABILITY"}},{"request":{"is_tagged":true,"tag":"a0001","command":"LOGIN","username":"\"neulingern\"","password":"\"password\""}},{"request":{"is_tagged":true,"tag":"a0002","command":"LIST"}}]})",
                true,
                false
            },
            // Test 2: Single line request
            {
                "Single line request continuation",
                "a0001 LOGIN \"neulingern\" \"password\"\r\n",
                R"({"imap":[{"request":{"is_tagged":true,"tag":"a0001","command":"LOGIN","username":"\"neulingern\"","password":"\"password\""}}]})",
                true,
                false
            },
            // Test 3: Multi-line responses (mixed tagged/untagged)
            {
                "Multi-line responses (mixed tagged/untagged)",
                "* CAPABILITY IMAP4 IMAP4rev1 IDLE\r\na0000 OK CAPABILITY completed.\r\n",
                R"({"imap":[{"response":{"is_tagged":false,"type":"capability","data":"IMAP4 IMAP4rev1 IDLE"}},{"response":{"is_tagged":true,"tag":"a0000","status":"OK","text":"CAPABILITY completed."}}]})",
                false,
                false
            },
            // Test 4: Single line response
            {
                "Single line response continuation",
                "a0001 OK LOGIN completed.\r\n",
                R"({"imap":[{"response":{"is_tagged":true,"tag":"a0001","status":"OK","text":"LOGIN completed."}}]})",
                false,
                false
            },
            
            // ================================================================
            // NEGATIVE TEST CASES (Tests 5-6)
            // ================================================================
            
            // Test 5: Multi-line with garbage on both lines
            {
                "Negative: Multi-line all garbage",
                "\x00\xFF\xFE\x01\x02garbage\r\n\x00\xFF\xFE\x01\x02garbage\r\n",
                nullptr,  // No expected JSON for negative tests
                true,
                true
            },
            // Test 6: Missing CRLF terminator
            {
                "Negative: Missing CRLF",
                "a004 CAPABILITY",  // No \r\n at the end
                nullptr,  // No expected JSON for negative tests
                true,
                true
            },
            
            // ================================================================
            // IMAP4rev2-SPECIFIC TESTS (Tests 7-8)
            // ================================================================
            
            // Test 7: UTF-8 in credentials
            {
                "IMAP4rev2: UTF-8 in credentials",
                "a001 LOGIN \"用户@example.com\" \"密码123\"\r\n",
                R"({"imap":[{"request":{"is_tagged":true,"tag":"a001","command":"LOGIN","username":"\"\u7528\u6237@example.com\"","password":"\"\u5bc6\u7801123\""}}]})",
                true,
                false
            },
            // Test 8: New IMAP4rev2 keywords
            {
                "IMAP4rev2: New keywords",
                "* FLAGS (\\\\Seen \\\\Answered $Forwarded $MDNSent)\r\n",
                "{\"imap\":[{\"response\":{\"is_tagged\":false,\"type\":\"data\",\"data\":\"FLAGS (\\\\\\\\Seen \\\\\\\\Answered $Forwarded $MDNSent)\"}}]}",
                false,
                false
            }
        };
        
        // Run all tests in a single loop
        for (size_t i = 0; i < sizeof(all_tests) / sizeof(all_tests[0]); i++) {
            if (!run_test_case(all_tests[i], i + 1, output)) {
                return false;
            }
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
