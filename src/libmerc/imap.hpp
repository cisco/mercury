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
#include "lex.h"
#include "decimal_int.hpp" 

namespace imap {

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

    // Parser for IMAP literals (e.g., {size}\r\n or {size+}\r\n)
    struct literal_parser : public datum {
        bool is_synchronizing = true;
        size_t literal_size = 0;
        datum literal_data;
        
        literal_parser() = default;
        
        literal_parser(datum &d) {
            const uint8_t *start_pos = d.data;
            
            literal_byte<'{'> left_brace{d};
            if (d.is_null()) {
                this->set_null();
                return;
            }
            
            decimal_integer<uint32_t> size_parser{d};
            if (d.is_null()) {
                this->set_null();
                return;
            }
            literal_size = size_parser.get_value();
            
            // BUGFIX: decimal_integer's accumulate_digits() consumes one character past the last digit
            // It reads a character, increments the pointer, then checks if it's a digit
            // When it encounters a non-digit (like '}' or '+'), the pointer is already past it
            // We need to back up by one character to re-read it
            if (d.is_not_empty()) {
                d.data--;
            }
            
            // Check for '+' (indicates non-synchronizing literal)
            if (d.is_not_empty() && d.data[0] == '+') {
                is_synchronizing = false;
                d.skip(1); 
            }
            
            literal_byte<'}'> right_brace{d};
            if (d.is_null()) {
                this->set_null();
                return;
            }
            
            crlf delimiter{d};
            if (d.is_null()) {
                this->set_null();
                return;
            }
            
            if (!is_synchronizing) {
                if (d.length() >= (ssize_t)literal_size) {
                    literal_data.data = d.data;
                    literal_data.data_end = d.data + literal_size;
                    d.skip(literal_size);
                    
                    this->data = start_pos;
                    this->data_end = d.data;
                } else {
                    this->set_null();
                    d.set_null();
                    return;
                }
            } else {
                // Synchronizing literal - set datum base class pointers
                this->data = start_pos;
                this->data_end = d.data;
            }
        }
        
        void write_json(json_object &o, const char *key) const {
            if (this->is_null()) {
                return;
            }
            
            json_object lit_obj{o, key};
            lit_obj.print_key_uint("size", literal_size);
            lit_obj.print_key_bool("synchronizing", is_synchronizing);
            
            if (!is_synchronizing && literal_data.is_not_empty()) {
                lit_obj.print_key_json_string("data", literal_data);
            }
            
            lit_obj.close();
        }
    };

    // Extracts one logical IMAP request (handles non-synchronizing literals)
    // A logical request may span multiple text lines if it contains {size+}\r\n<data>
    // Uses literal_parser to handle all literal syntax, making it simple and consistent.
    struct imap_logical_request : public datum {
        imap_logical_request(datum &d) {
            if (d.is_empty()) {
                this->set_null();
                d.set_null();
                return;
            }
            
            this->data = d.data;
            datum scanner = d;
            
            // Scan for logical request end, handling literals
            while (scanner.is_not_empty()) {
                
                // Try to detect a literal using lookahead
                lookahead<literal_parser> lit_check{scanner};
                if (lit_check) {
                    // Found a literal - parse it
                    literal_parser lit{scanner};
                    
                    if (lit.is_null()) {
                        // Parsing failed, shouldn't happen after successful lookahead
                        scanner.skip(1);
                        continue;
                    }
                    
                    // Check if it's synchronizing or non-synchronizing
                    if (lit.is_synchronizing) {
                        // Synchronizing literal - logical request ends here
                        // (client must wait for server "+ " response before continuing)
                        this->data_end = scanner.data;
                        d.data = scanner.data;
                        return;
                    }
                    else {
                        // Non-synchronizing literal - literal_parser already consumed
                        // the {size+}\r\n<data> sequence. Just continue scanning
                        // for more content or the final \r\n
                        continue;
                    }
                }
                
                // No literal at current position - check if CURRENT position is \r\n
                // (not lookahead - we only want to stop if we're AT the ending)
                lookahead<crlf> crlf_check{scanner};
                if (crlf_check) {
                    // Found request ending at current position
                    crlf delimiter{scanner};
                    this->data_end = scanner.data;
                    d.data = scanner.data;
                    return;
                }
                
                // Regular character, skip it and continue
                scanner.skip(1);
            }
            
            // Reached end without finding \r\n - incomplete request
            this->set_null();
            d.set_null();
        }
    };

    struct field_or_literal {
        enum class field_type {
            INVALID,
            LITERAL,
            QUOTED,
            ATOM
        };
        
        field_type type;
        literal_parser literal;
        datum content;
        
        field_or_literal(datum &d) : type(field_type::INVALID), literal(), content() {
            if (d.is_not_readable()) {
                d.set_null();
                return;
            }
            
            uint8_t first_char = d.data[0];
            
            switch (first_char) {
                case '{': {
                    // Case 1: Literal parser
                    type = field_type::LITERAL;
                    literal = literal_parser{d};
                    if (literal.is_null()) {
                        content.set_null();
                        d.set_null();
                    } else {
                        content = literal.literal_data;
                    }
                    break;
                }
                
                case '"': {
                    // Case 2: Quoted string parser
                    type = field_type::QUOTED;
                    content = quoted_string_parser{d};
                    if (content.is_null()) {
                        d.set_null();
                    }
                    break;
                }
                
                default: {
                    // Case 3: Normal parser (atom) - up to space or \r
                    type = field_type::ATOM;
                    content = imap_token{d};
                    if (content.is_null()) {
                        d.set_null();
                    }
                    break;
                }
            }
        }
        
        void write_json(json_object &o, const char *key) const {
            if (type == field_type::INVALID || (content.is_null() && type != field_type::LITERAL)) {
                return;
            }
            
            switch (type) {    
                case field_type::LITERAL:
                    literal.write_json(o, key);
                    break;
                    
                case field_type::QUOTED:
                case field_type::ATOM:
                    if (content.is_not_empty()) {
                        o.print_key_json_string(key, content);
                    }
                    break;
            }
        }
        
        bool is_not_empty() const {
            if (type == field_type::INVALID) {
                return false;
            }
            return content.is_not_empty() || type == field_type::LITERAL;
        }
        
        bool is_valid() const {
            if (type == field_type::INVALID) {
                return false;
            }
            return !content.is_null() || (type == field_type::LITERAL && !literal.is_null());
        }
    };

    // Parser for LOGIN command arguments
    // LOGIN <username> <password>
    // LOGIN "<username>" "<password>"
    // LOGIN {<size>}
    // LOGIN {<size>+}{username} {<size>+}{password}
    struct login_arguments {
        field_or_literal username;
        optional<literal_byte<' '>> sp;
        optional<field_or_literal> password;
        crlf delimiter;
        bool isValid;
        
        login_arguments(datum &d) : 
            username(d),
            sp(d),
            password(d),
            delimiter(d),
            isValid{false}
        {
            if (!username.is_valid() || !d.is_empty()) {
                return;
            }
            
            isValid = true;
            
            if (username.type == field_or_literal::field_type::LITERAL && 
                username.literal.is_synchronizing) {
                // Synchronizing literal: sp and password must be absent
                isValid = !sp && !password;
            } else {
                // Require all three fields
                isValid = sp && password;
            }
        }
        
        void write_json(json_object &o) const {
            username.write_json(o, "username");
            if (password) {
                password.value.write_json(o, "password");
            }
        }
        
        bool is_not_empty() const {
            return isValid;
        }
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
    struct request {
        up_to_required_byte<' '> tag;
        literal_byte<' '> sp1;
        alphabetic command;
        optional<literal_byte<' '>> sp2;
        datum arguments;
        bool isValid;
        
        request(datum &d) :
            tag{d},
            sp1{d},
            command{d},
            sp2{d},
            arguments{},
            isValid{false}
        {
            if (tag.is_empty() || command.is_empty()) {
                d.set_null();
                return;
            }
            
            // Validate command is whitelisted
            if (!is_valid_imap_command(command)) {
                d.set_null();
                return;
            }
            
            // Validate that it ends with \r\n
            std::array<uint8_t, 2> crlf_suffix{'\r', '\n'};
            if (!d.ends_with(crlf_suffix)) {
                d.set_null();
                return;
            }
            
            arguments = d;
            isValid = true;
            d.data = d.data_end;
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
                datum args_copy = arguments;
                login_arguments login_args{args_copy};
                login_args.write_json(record);
            } else if (is_authenticate && arguments.is_not_empty()) {
                datum args_copy = arguments;
                
                // Remove trailing \r\n for cleaner output
                if (args_copy.length() >= 2) {
                    args_copy.trim(2);
                }
                
                record.print_key_json_string("auth_type", args_copy);
                
            } else if (arguments.is_not_empty()) {
                // Other commands: just report args_length
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
        
        // Protocol identification via logical request validation:
        // Valid IMAP requests MUST start with either a tagged request (tag SP command) or
        // a continuation request. Uses imap_logical_request which handles non-synchronizing
        // literals {size+}\r\n<data> as atomic units spanning multiple text lines.
        void parse(datum &d) {
            lookahead<imap_logical_request> req_check{d};
            if (!req_check) {
                return;
            }
            
            imap_logical_request logical_req{d};
            
            // Try parsing as normal request (tag + command)
            if (lookahead<request>{logical_req}) {
                datum req_copy = logical_req;
                request req{req_copy};
                if (req.is_not_empty()) {
                    // It's a tagged request (may contain non-sync literals)
                    valid = true;
                    is_tagged_request = true;  
                }
                return;
            }
            
            // Try parsing as continuation request (must be alone per RFC)
            if (lookahead<continuation_request>{logical_req}) {
                datum cont_copy = logical_req;
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
                // Tagged request: can contain non-synchronizing literals
                while (temp.is_not_empty()) {
                
                    lookahead<imap_logical_request> req_check{temp};
                    if (!req_check) {
                        break;
                    }
                    
                    imap_logical_request logical_req{temp};
                    
                    // Parse as logical request (handles {size+} literals)
                    if (lookahead<request>{logical_req}) {
                        datum req_copy = logical_req;
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
        // LOGIN COMMAND TEST CASES
        // ================================================================
        
        // Test Case 1: LOGIN <username> <password> (unquoted atoms)
        if (!test_json_output<imap::imap_requests>(
            datum{"a001 LOGIN mcgrew mypassword\r\n"},
            datum{R"({"imap":{"requests":[{"is_tagged":true,"tag":"a001","command":"LOGIN","username":"mcgrew","password":"mypassword"}]}})"}
        )) {
            return false;
        }
        
        // Test Case 2: LOGIN "<username>" "<password>" (quoted strings)
        if (!test_json_output<imap::imap_requests>(
            datum{"a002 LOGIN \"john@example.com\" \"secret pass\"\r\n"},
            datum{R"({"imap":{"requests":[{"is_tagged":true,"tag":"a002","command":"LOGIN","username":"\"john@example.com\"","password":"\"secret pass\""}]}})"}
        )) {
            return false;
        }
        
        // Test Case 3: LOGIN {<size>}\r\n (synchronizing literal)
        if (!test_json_output<imap::imap_requests>(
            datum{"a003 LOGIN {6}\r\n"},
            datum{R"({"imap":{"requests":[{"is_tagged":true,"tag":"a003","command":"LOGIN","username":{"size":6,"synchronizing":true}}]}})"}
        )) {
            return false;
        }
        
        // Test Case 4: LOGIN {<size>+}<data> {<size>+}<data>\r\n (non-synchronizing literals)
        if (!test_json_output<imap::imap_requests>(
            datum{"a004 LOGIN {6+}\r\nalice1 {8+}\r\npass1234\r\n"},
            datum{R"({"imap":{"requests":[{"is_tagged":true,"tag":"a004","command":"LOGIN","username":{"size":6,"synchronizing":false,"data":"alice1"},"password":{"size":8,"synchronizing":false,"data":"pass1234"}}]}})"}
        )) {
            return false;
        }
        
        // ================================================================
        // NEGATIVE TEST CASES - LOGIN
        // ================================================================
        
        // Negative 1: Missing password
        if (test_json_output<imap::imap_requests>(
            datum{"a005 LOGIN username\r\n"},
            datum{"{}"}
        )) {
            return false;
        }
        
        // Negative 2: Missing space between username and password
        if (test_json_output<imap::imap_requests>(
            datum{"a006 LOGIN usernamepassword\r\n"},
            datum{"{}"}
        )) {
            return false;
        }
        
        // Negative 3: Synchronizing literal with extra data (malformed)
        if (test_json_output<imap::imap_requests>(
            datum{"a007 LOGIN {3}\r\n extrabaddata\r\n"},
            datum{"{}"}
        )) {
            return false;
        }
        
        // Negative 4: Unclosed quoted string
        if (test_json_output<imap::imap_requests>(
            datum{"a008 LOGIN \"unclosed password\r\n"},
            datum{"{}"}
        )) {
            return false;
        }
        
        // Negative 5: Invalid literal size (negative)
        if (test_json_output<imap::imap_requests>(
            datum{"a009 LOGIN {-5}\r\n"},
            datum{"{}"}
        )) {
            return false;
        }
        
        /*
        // ================================================================
        // COMMENTED OUT - OTHER TEST CASES
        // ================================================================
        
        // Multi-line IMAP requests
        if (!test_json_output<imap::imap_requests>(
            datum{"a0000 CAPABILITY\r\na0001 LOGIN \"neulingern\" \"password\"\r\na0002 LIST\r\n"},
            datum{R"({"imap":{"requests":[{"is_tagged":true,"tag":"a0000","command":"CAPABILITY"},{"is_tagged":true,"tag":"a0001","command":"LOGIN","username":"\"neulingern\"","password":"\"password\""},{"is_tagged":true,"tag":"a0002","command":"LIST"}]}})"}
        )) {
            return false;
        }
        
        // Single line request
        if (!test_json_output<imap::imap_requests>(
            datum{"a0001 LOGIN \"neulingern\" \"password\"\r\n"},
            datum{R"({"imap":{"requests":[{"is_tagged":true,"tag":"a0001","command":"LOGIN","username":"\"neulingern\"","password":"\"password\""}]}})"}
        )) {
            return false;
        }
        
        // UTF-8 in credentials (IMAP4rev2)
        if (!test_json_output<imap::imap_requests>(
            datum{"a001 LOGIN \"用户@example.com\" \"密码123\"\r\n"},
            datum{R"({"imap":{"requests":[{"is_tagged":true,"tag":"a001","command":"LOGIN","username":"\"\u7528\u6237@example.com\"","password":"\"\u5bc6\u7801123\""}]}})"}
        )) {
            return false;
        }
        */
        
        /*
        // ================================================================
        // COMMENTED OUT - POSITIVE TEST CASES - Responses
        // ================================================================
        
        // Multi-line responses (mixed tagged/untagged)
        if (!test_json_output<imap::imap_responses>(
            datum{"* CAPABILITY IMAP4 IMAP4rev1 IDLE\r\na0000 OK CAPABILITY completed.\r\n"},
            datum{R"({"imap":{"responses":[{"is_tagged":false,"type":"capability","data":"IMAP4 IMAP4rev1 IDLE"},{"is_tagged":true,"tag":"a0000","status":"OK","text":"CAPABILITY completed."}]}})"}
        )) {
            return false;
        }
        
        // Single line response
        if (!test_json_output<imap::imap_responses>(
            datum{"a0001 OK LOGIN completed.\r\n"},
            datum{R"({"imap":{"responses":[{"is_tagged":true,"tag":"a0001","status":"OK","text":"LOGIN completed."}]}})"}
        )) {
            return false;
        }
        
        // New IMAP4rev2 keywords
        if (!test_json_output<imap::imap_responses>(
            datum{"* FLAGS (\\\\Seen \\\\Answered $Forwarded $MDNSent)\r\n"},
            datum{"{\"imap\":{\"responses\":[{\"is_tagged\":false,\"type\":\"data\",\"data\":\"FLAGS (\\\\\\\\Seen \\\\\\\\Answered $Forwarded $MDNSent)\"}]}}"}
        )) {
            return false;
        }
        
        // ================================================================
        // COMMENTED OUT - CONTINUATION RESPONSE VALIDATION TESTS
        // ================================================================
        
        // Valid continuation response with base64 data (AUTHENTICATE)
        if (!test_json_output<imap::imap_responses>(
            datum{"+ YGgGCSqGSIb3EgECAgIAb1kwV6A=\r\n"},
            datum{R"({"imap":{"responses":[{"type":"continuation","data":"YGgGCSqGSIb3EgECAgIAb1kwV6A="}]}})"}
        )) {
            return false;
        }
        
        // Valid continuation response with UTF-8 text
        if (!test_json_output<imap::imap_responses>(
            datum{"+ Ready for additional command text\r\n"},
            datum{R"({"imap":{"responses":[{"type":"continuation","data":"Ready for additional command text"}]}})"}
        )) {
            return false;
        }
        
        // Continuation response with literal specification (for LOGIN/AUTHENTICATE)
        // Current implementation treats {16} as raw text, not a parsed literal
        if (!test_json_output<imap::imap_responses>(
            datum{"+ \r\n"},
            datum{R"({"imap":{"responses":[{"type":"continuation"}]}})"}
        )) {
            return false;
        }
             
        // Invalid continuation response - invalid data (not base64 or UTF-8)
        if (test_json_output<imap::imap_responses>(
            datum{"+ \xFF\xFE\xFD\xFC\xFB\xFA\r\n"},
            datum{""}
        )) {
            return false;
        }
        
        // ================================================================
        // COMMENTED OUT - CONTINUATION REQUEST TESTS (Client to Server)
        // ================================================================
        
        // Continuation request with literal specification {16}
        // This represents: "Ready for 16 bytes of literal data"
        if (!test_json_output<imap::imap_requests>(
            datum{"{16}\r\n"},
            datum{R"({"imap":{"requests":[{"is_tagged":false,"type":"continuation","data":"{16}"}]}})"}
        )) {
            return false;
        }
        
        // ================================================================
        // COMMENTED OUT - NEGATIVE TEST CASES - Should fail to parse
        // ================================================================
        
        // Multi-line with garbage on both lines - should fail
        if (test_json_output<imap::imap_requests>(
            datum{"\x00\xFF\xFE\x01\x02garbage\r\n\x00\xFF\xFE\x01\x02garbage\r\n"},
            datum{""}
        )) {
            return false;
        }
        
        // Missing CRLF terminator - should fail
        if (test_json_output<imap::imap_requests>(
            datum{"a004 CAPABILITY"},
            datum{""}
        )) {
            return false;
        }
        
        // Multiple junk lines with invalid commands - should not create empty imap array element
        if (!test_json_output<imap::imap_requests>(
            datum{"junk line one\r\njunk line two\r\n"},
            datum{"{}"}
        )) {
            return false;
        }
        */
        
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
