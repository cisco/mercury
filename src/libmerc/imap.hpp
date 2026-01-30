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
#include "perfect_hash.h"
#include "exposed_creds_types.h"

namespace imap {

    // RFC 3501 Section 9 Formal Syntax:
    //   atom            = 1*ATOM-CHAR
    //   ATOM-CHAR       = <any CHAR except atom-specials>
    //   atom-specials   = "(" / ")" / "{" / SP / CTL / list-wildcards /
    //                     quoted-specials / resp-specials
    //   list-wildcards  = "%" / "*"
    //   quoted-specials = DQUOTE / "\"
    //   resp-specials   = "]"
    //   CTL             = %x00-1F / %x7F
    //
    class imap_atom : public one_or_more<imap_atom> {
    public:
        inline static bool in_class(uint8_t x) {
            // CHAR is %x01-7F, so reject NUL and non-ASCII
            if (x == 0x00 || x > 0x7F) {
                return false;
            }
            // Reject CTL: %x00-1F and %x7F
            if (x <= 0x1F || x == 0x7F) {
                return false;
            }
            // Reject atom-specials: ( ) { SP % * " \ ]
            switch (x) {
                case '(':   // 0x28
                case ')':   // 0x29
                case '{':   // 0x7B
                case ' ':   // 0x20 SP
                case '%':   // 0x25 list-wildcard
                case '*':   // 0x2A list-wildcard
                case '"':   // 0x22 quoted-special (DQUOTE)
                case '\\':  // 0x5C quoted-special
                case ']':   // 0x5D resp-special
                    return false;
                default:
                    return true;
            }
        }
    };

    // Parser for quoted strings (includes quotes)
    // RFC 3501 Section 4.3: "A quoted string is a sequence of zero or
    // more 7-bit characters, excluding CR and LF, with double quote
    // (<">) characters at each end."
    class quoted_string_parser : public datum {
    public:
        quoted_string_parser(datum &d) {
            const uint8_t *start = d.data;
            literal_byte<'"'> lquote{d};
            if (d.is_null()) {
                this->set_null();
                return;
            }
            escaped_string_up_to<'"'> body{d};
            if (body.is_null()) {
                this->set_null();
                return;
            }
            this->data = start;
            this->data_end = d.data;
        }
    };
    
    // Parser for IMAP token up to space or CR (for status/command words)
    // RFC 3501 Section 4.1: "An atom consists of one or more non-special
    // characters."
    class imap_token : public datum {
    public:
        imap_token(datum &d) {
            uint8_t delim = this->parse_up_to_delimiters(d, ' ', '\r');
            if (delim == 0 || this->is_empty()) {
                this->set_null();
                d.set_null();
            }
        }
    };

    // Extracts one complete line including \r\n
    class imap_line : public datum {
    public:
        imap_line(datum &d) {
            const uint8_t *line_start = d.data;
            
            up_to_required_byte<'\r'> line_content{d};
            if (line_content.is_null()) {
                this->set_null();
                return;
            }
        
            crlf delimiter{d};
            if (d.is_null()) {
                this->set_null();
                return;
            }
            
            this->data = line_start;
            this->data_end = d.data;
        }
    };

    // Parser for IMAP literals (e.g., {size}\r\n or {size+}\r\n)
    // RFC 3501 Section 4.3: "A literal is a sequence of zero or more
    // octets (including CR and LF), prefix-quoted with an octet count
    // in the form of an open brace ("{"), the number of octets, close
    // brace ("}"), and CRLF."
    // Note: {size+} is non-synchronizing literal (RFC 2088 LITERAL+)
    class literal_parser : public datum {
        bool is_synchronizing = true;
        size_t literal_size = 0;
        datum literal_data;
        
    public:
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
            
            // Check for '+' (indicates non-synchronizing literal)
            if (d[0] == '+') {
                is_synchronizing = false;
                d.skip(1); 
            }
            
            literal_byte<'}'> right_brace{d};
            if (d.is_null()) {
                this->set_null();
                return;
            }
            
            if (!is_synchronizing) {
                crlf delimiter{d};
                if (d.is_null()) {
                    this->set_null();
                    return;
                }
                
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
                this->data = start_pos;
                this->data_end = d.data;
            }
        }
        
        bool get_is_synchronizing() const { return is_synchronizing; }
        const datum& get_literal_data() const { return literal_data; }
        
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
    class imap_logical_request : public datum {
    public:
        imap_logical_request(datum &d) {
            if (d.is_empty()) {
                this->set_null();
                d.set_null();
                return;
            }
            
            this->data = d.data;
            datum scanner = d;
            
            while (scanner.is_not_empty()) {
                lookahead<literal_parser> lit_check{scanner};
                if (lit_check) {
                    literal_parser lit{scanner};
                    if (lit.get_is_synchronizing()) {
                        crlf delimiter{scanner};
                        if (scanner.is_not_null()) {
                            this->data_end = scanner.data;
                            d.data = scanner.data;
                            return;
                        } else {
                            this->set_null();
                            d.set_null();
                            return;
                        }
                    }
                    else {
                        continue;
                    }
                }
                
                // Final \r\n
                lookahead<crlf> crlf_check{scanner};
                if (crlf_check) {
                    crlf delimiter{scanner};
                    this->data_end = scanner.data;
                    d.data = scanner.data;
                    return;
                }
            
                scanner.skip(1);
            }
            
            // No Final \r\n found - request is incomplete
            this->set_null();
            d.set_null();
        }
    };

    // Parser for IMAP string/astring fields
    // RFC 3501 Section 4.3: "A string is in one of two forms: either
    // literal or quoted string."
    // astring = atom or string (used for userid, password, etc.)
    class field_or_literal {
    public:
        enum class field_type {
            INVALID,
            LITERAL,
            QUOTED,
            ATOM
        };
        
    private:
        field_type type;
        literal_parser literal;
        datum content;
        
    public:
        field_or_literal(datum &d) : type{field_type::INVALID}, literal{}, content{} {
            if (d.is_not_readable()) {
                d.set_null();
                return;
            }
            
            // Check for literal
            if (d[0] == '{') {
                type = field_type::LITERAL;
                literal = literal_parser{d};
                if (literal.is_null()) {
                    content.set_null();
                } else {
                    content = literal.get_literal_data();
                }
            }
            // Check for quoted string
            else if (d[0] == '"') {
                type = field_type::QUOTED;
                content = quoted_string_parser{d};
            }
            // Atom
            else {
                type = field_type::ATOM;
                content = imap_token{d};
            }
        }

        bool is_valid() const {
            if (type == field_type::INVALID) {
                return false;
            }
            return !content.is_null() || (type == field_type::LITERAL && !literal.is_null());
        }
        
        field_type get_type() const { return type; }
        const literal_parser& get_literal() const { return literal; }
        
        void write_json(json_object &o, const char *key) const {
            if (!is_valid()) {
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
                    
                case field_type::INVALID:
                    break;
            }
        }
    };

    // Parser for LOGIN command arguments
    // RFC 3501 Section 6.2.3: "The LOGIN command identifies the client
    // to the server and carries the plaintext password authenticating
    // this user." Arguments: userid SP password (both astring)
    // Handles: LOGIN user pass | LOGIN "user" "pass" | LOGIN {n+}\r\nuser {n+}\r\npass
    // For synchronizing literals {n}, only partial command seen (awaits continuation)
    class login_arguments {
        field_or_literal username;
        optional<literal_byte<' '>> sp;
        optional<field_or_literal> password;
        crlf delimiter;
        bool isValid;
        
    public:
        login_arguments(datum &d) : 
            username(d),
            sp(d),
            password(d),
            delimiter(d),
            isValid{false}
        {
            if (!username.is_valid()) {
                return;
            }
            
            if (username.get_type() == field_or_literal::field_type::LITERAL && 
                username.get_literal().get_is_synchronizing()) {
                isValid = !sp && !password && d.is_not_null() && d.is_empty();
            } else {
                isValid = sp && password && d.is_not_null() && d.is_empty();
            }
        }
        
        void write_json(json_object &o) const {
            if (!isValid) {
                return;
            }
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
    class response_data {
        imap_token status;
        optional<literal_byte<' '>> sp;
        datum additional_data;
        
    public:
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

    // Parser for server continuation responses: + SP (resp-text / base64) CRLF (RFC 3501 Section 7.5)
    // Used internally by imap_responses multi-line parser
    class continuation_response {
        literal_byte<'+'> plus;
        literal_byte<' '> sp;  // Space is mandatory per RFC
        up_to_required_byte<'\r'> data;
        crlf delimiter;
        bool isValid;
        
    public:
        continuation_response(datum &d) :
            plus{d},
            sp{d},
            data{d},
            delimiter{d},
            isValid{false}
        {
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

    // Parser for client continuation data: raw data or cancel (*) CRLF (RFC 3501 Section 7.5)
    // Used internally by imap_requests multi-line parser
    class continuation_request {
        up_to_required_byte<'\r'> data;
        crlf delimiter;
        bool isValid;
        
    public:
        continuation_request(datum &d) :
            data{d},
            delimiter{d},
            // continuation_request can have raw bytes so not possible to validate like continuation_response
            isValid{d.is_empty()}
        {
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
                if (data.length() == 1 && data[0] == '*') {
                    record.print_key_string("action", "cancel");
                } else {
                    record.print_key_json_string("data", data);
                }
            }
        }

        bool is_not_empty() const { return isValid; }
    };

    // Validate if command is a known IMAP command per RFC 3501
    // RFC 3501 Section 6: Commands are organized by state - any (6.1),
    // not authenticated (6.2), authenticated (6.3), and selected (6.4).
    // Commands are case-insensitive. Extension commands start with "X".
    static bool is_valid_imap_command(const datum &cmd) {
        static perfect_hash_set imap_commands{
            // command-any: Valid in all states
            "capability", "logout", "noop",
            // command-nonauth: Valid in Not Authenticated state
            "login", "authenticate", "starttls",
            // command-auth: Valid in Authenticated or Selected state
            "append", "create", "delete", "examine", "list", "lsub",
            "rename", "select", "status", "subscribe", "unsubscribe",
            // command-select: Valid only in Selected state
            "check", "close", "expunge", "copy", "fetch", "store", "uid", "search"
        };

        if (imap_commands.contains(cmd)) {
            return true;
        }

        // IMAP extensions start with 'X'
        if (cmd[0] == 'X' || cmd[0] == 'x') {
            return true;
        }

        return false;
    }

    // IMAP client request parser
    // RFC 3501 Section 2.2.1: Format: tag SP command [SP args] CRLF
    // Commands are case-insensitive.
    class request {
        up_to_required_byte<' '> tag;
        literal_byte<' '> sp1;
        imap_atom command;
        optional<literal_byte<' '>> sp2;
        datum arguments;
        bool isValid;
        
    public:
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
            
            // Validate LOGIN arguments if this is a LOGIN command
            if (command.case_insensitive_match("login") && arguments.is_not_empty()) {
                datum args_copy = arguments;
                login_arguments login_args{args_copy};
                if (!login_args.is_not_empty()) {
                    isValid = false;
                    return;
                }
            }
            
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

        datum get_command() const { return command; }

        datum get_arguments() const { return arguments; }
    };

    // IMAP server response parser
    // RFC 3501 Section 2.2.2
    // Untagged: "*" SP data CRLF | Tagged: tag SP (OK|NO|BAD) SP text CRLF
    class response {
        up_to_required_byte<' '> tag_or_star;      
        literal_byte<' '> sp1;                      
        up_to_required_byte<'\r'> response_data_field;    
        crlf delimiter;
        bool isValid;
        bool is_untagged;

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
                    if (data_copy[0] == ' ') {
                        data_copy.skip(1);
                    }
                    if (data_copy.is_not_empty()) {
                        imap_response.print_key_json_string("text", data_copy);
                    }
                    break;
                    
                case untagged_type::capability:
                    // capability-data: * CAPABILITY ...
                    imap_response.print_key_string("type", "capability");
                    if (data_copy[0] == ' ') {
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

    public:
        response(datum &d) :
            tag_or_star{d},
            sp1{d},
            response_data_field{d},
            delimiter{d},
            isValid{tag_or_star.is_not_empty() && response_data_field.is_not_empty() && d.is_empty()},
            is_untagged{false}
        {
            if (isValid) {
                // Check if this is an untagged response (starts with "*")
                is_untagged = (tag_or_star.length() == 1 && tag_or_star[0] == '*');
                
                // Tagged responses MUST start with status code: ok, no, or bad
                if (!is_untagged) {
                    datum check_status = response_data_field;
                    imap_token status_code{check_status};
                
                    if (classify_untagged_response(status_code) != untagged_type::resp_cond_state) {
                        isValid = false;
                        d.set_null();
                    }
                }
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
            
                if (data_copy[0] == ' ') {
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

        void parse(datum &d) {
            lookahead<imap_logical_request> req_check{d};
            if (!req_check) {
                return;
            }
            
            imap_logical_request logical_req{d};
            
            // Try parsing as normal request (tag + command)
            lookahead<request> req_lookahead{logical_req};
            if (req_lookahead) {
                datum req_copy = logical_req;
                request req{req_copy};
                if (req.is_not_empty()) {
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
                // Tagged request
                while (temp.is_not_empty()) {
                
                    lookahead<imap_logical_request> req_check{temp};
                    if (!req_check) {
                        break;
                    }
                    
                    imap_logical_request logical_req{temp};
                    
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

        // Check for exposed credentials in IMAP request
        // Per RFC 3501, LOGIN/AUTHENTICATE commands are single commands
        // that require server response before client can send more
        exposed_creds_type check_credential_exposure() const {
            if (!valid || !is_tagged_request) {
                return exposed_creds_none;
            }
            
            // Parse first tagged request (already validated by parse())
            datum temp = requests;
            imap_logical_request logical_req{temp};
            request req{logical_req};
            
            // Get command from the request
            datum cmd = req.get_command();
            
            // LOGIN command always exposes plaintext credentials
            if (cmd.case_insensitive_match("login")) {
                return exposed_creds_plaintext;
            }
            
            // AUTHENTICATE command - depends on SASL mechanism
            if (cmd.case_insensitive_match("authenticate")) {
                datum args = req.get_arguments();
                if (args.is_not_empty()) {
                    // Extract auth mechanism (first token)
                    imap_token auth_mechanism{args};
                    
                    // Plaintext mechanisms
                    if (auth_mechanism.case_insensitive_match("plain") ||
                        auth_mechanism.case_insensitive_match("login")) {
                        return exposed_creds_plaintext;
                    }
                    
                    // Derived/hashed mechanisms (challenge-response)
                    if (auth_mechanism.case_insensitive_match("cram-md5") ||
                        auth_mechanism.case_insensitive_match("digest-md5") ||
                        auth_mechanism.case_insensitive_match("scram-sha-1") ||
                        auth_mechanism.case_insensitive_match("scram-sha-256") ||
                        auth_mechanism.case_insensitive_match("ntlm")) {
                        return exposed_creds_derived;
                    }
                    
                    // Token-based mechanisms
                    if (auth_mechanism.case_insensitive_match("oauth") ||
                        auth_mechanism.case_insensitive_match("oauthbearer") ||
                        auth_mechanism.case_insensitive_match("xoauth2") ||
                        auth_mechanism.case_insensitive_match("gssapi")) {
                        return exposed_creds_token;
                    }
                }
            }
            
            return exposed_creds_none;
        }
    };

    // Multi-line IMAP response parser
    // RFC 3501 Section 7: Server responses are line-based (CRLF terminated).
    // Can be continuation ("+"), untagged ("*"), or tagged (completion).
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
                    is_continuation_response = true;
                }
                return;
            }
            
            // Try parsing as normal response (can be multi-line)
            if (lookahead<response>{line}) {
                datum resp_copy = line;
                response resp{resp_copy};
                if (resp.is_not_empty()) {
                    valid = true;
                    is_continuation_response = false;
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
        // POSITIVE TEST CASES - Login
        // ================================================================
        
        // LOGIN <username> <password> (unquoted atoms)
        if (!test_json_output<imap::imap_requests>(
            datum{"a001 LOGIN username password\r\n"},
            datum{R"xxx({"imap":{"requests":[{"is_tagged":true,"tag":"a001","command":"LOGIN","username":"username","password":"password"}]}})xxx"}
        )) {
            return false;
        }
        
        // LOGIN "<username>" "<password>" (quoted strings)
        if (!test_json_output<imap::imap_requests>(
            datum{"a002 LOGIN \"user@email.com\" \"password\"\r\n"},
            datum{R"xxx({"imap":{"requests":[{"is_tagged":true,"tag":"a002","command":"LOGIN","username":"\"user@email.com\"","password":"\"password\""}]}})xxx"}
        )) {
            return false;
        }
        
        // LOGIN {<size>}\r\n (synchronizing literal)
        if (!test_json_output<imap::imap_requests>(
            datum{"a003 LOGIN {8}\r\n"},
            datum{R"xxx({"imap":{"requests":[{"is_tagged":true,"tag":"a003","command":"LOGIN","username":{"size":8,"synchronizing":true}}]}})xxx"}
        )) {
            return false;
        }
        
        // LOGIN {<size>+}<data> {<size>+}<data>\r\n (non-synchronizing literals)
        if (!test_json_output<imap::imap_requests>(
            datum{"a004 LOGIN {8+}\r\nusername {8+}\r\npassword\r\n"},
            datum{R"xxx({"imap":{"requests":[{"is_tagged":true,"tag":"a004","command":"LOGIN","username":{"size":8,"synchronizing":false,"data":"username"},"password":{"size":8,"synchronizing":false,"data":"password"}}]}})xxx"}
        )) {
            return false;
        }

        // Case-insensitive LOGIN command
        if (!test_json_output<imap::imap_requests>(
            datum{"a001 LoGiN username password\r\n"},
            datum{R"xxx({"imap":{"requests":[{"is_tagged":true,"tag":"a001","command":"LoGiN","username":"username","password":"password"}]}})xxx"}
        )) {
            return false;
        }
        
        // ================================================================
        // NEGATIVE TEST CASES - Login
        // ================================================================
        
        // Missing password
        if (!test_json_output<imap::imap_requests>(
            datum{"a005 LOGIN username\r\n"},
            datum{"{}"}
        )) {
            return false;
        }
            
        // Synchronizing literal with extra data (malformed)
        if (!test_json_output<imap::imap_requests>(
            datum{"a007 LOGIN {3}\r\n extrabaddata\r\n"},
            datum{R"xxx({"imap":{"requests":[{"is_tagged":true,"tag":"a007","command":"LOGIN","username":{"size":3,"synchronizing":true}}]}})xxx"}
        )) {
            return false;
        }
        
        // Unclosed quoted string
        if (!test_json_output<imap::imap_requests>(
            datum{"a008 LOGIN \"unclosed password\r\n"},
            datum{"{}"}
        )) {
            return false;
        }
        
        // Invalid literal size (negative)
        if (!test_json_output<imap::imap_requests>(
            datum{"a009 LOGIN {-5}\r\n"},
            datum{"{}"}
        )) {
            return false;
        }
        
        // ================================================================
        // POSITIVE TEST CASES - Requests
        // ================================================================
        
        // Multi-line IMAP requests
        if (!test_json_output<imap::imap_requests>(
            datum{"a0000 CAPABILITY\r\na0001 LOGIN \"username\" \"password\"\r\na0002 LIST\r\n"},
            datum{R"xxx({"imap":{"requests":[{"is_tagged":true,"tag":"a0000","command":"CAPABILITY","args_length":2},{"is_tagged":true,"tag":"a0001","command":"LOGIN","username":"\"username\"","password":"\"password\""},{"is_tagged":true,"tag":"a0002","command":"LIST","args_length":2}]}})xxx"}
        )) {
            return false;
        }
        
        // Single line request
        if (!test_json_output<imap::imap_requests>(
            datum{"a0001 LOGIN \"username\" \"password\"\r\n"},
            datum{R"xxx({"imap":{"requests":[{"is_tagged":true,"tag":"a0001","command":"LOGIN","username":"\"username\"","password":"\"password\""}]}})xxx"}
        )) {
            return false;
        }
        
        // UTF-8 in credentials (IMAP4rev2)
        if (!test_json_output<imap::imap_requests>(
            datum{"a001 LOGIN \"用户@example.com\" \"密码123\"\r\n"},
            datum{R"xxx({"imap":{"requests":[{"is_tagged":true,"tag":"a001","command":"LOGIN","username":"\"\u7528\u6237@example.com\"","password":"\"\u5bc6\u7801123\""}]}})xxx"}
        )) {
            return false;
        }
        
        // Extension command with digits and hyphens (X-GM-EXT-1)
        // RFC 3501 Section 6.5.1: x-command = "X" atom
        if (!test_json_output<imap::imap_requests>(
            datum{"a001 X-GM-EXT-1 arg1 arg2\r\n"},
            datum{R"xxx({"imap":{"requests":[{"is_tagged":true,"tag":"a001","command":"X-GM-EXT-1","args_length":11}]}})xxx"}
        )) {
            return false;
        }
            
        // ================================================================
        // POSITIVE TEST CASES - Responses
        // ================================================================
        
        // Multi-line responses (mixed tagged/untagged)
        if (!test_json_output<imap::imap_responses>(
            datum{"* CAPABILITY IMAP4 IMAP4rev1 IDLE\r\na0000 OK CAPABILITY completed.\r\n"},
            datum{R"xxx({"imap":{"responses":[{"is_tagged":false,"type":"capability","data":"IMAP4 IMAP4rev1 IDLE"},{"is_tagged":true,"tag":"a0000","status":"OK","text":"CAPABILITY completed."}]}})xxx"}
        )) {
            return false;
        }
        
        // Single line response
        if (!test_json_output<imap::imap_responses>(
            datum{"a0001 OK LOGIN completed.\r\n"},
            datum{R"xxx({"imap":{"responses":[{"is_tagged":true,"tag":"a0001","status":"OK","text":"LOGIN completed."}]}})xxx"}
        )) {
            return false;
        }
        
        // New IMAP4rev2 keywords
        if (!test_json_output<imap::imap_responses>(
            datum{"* FLAGS (\\\\Seen \\\\Answered $Forwarded $MDNSent)\r\n"},
            datum{R"xxx({"imap":{"responses":[{"is_tagged":false,"type":"data","data":"FLAGS (\\\\Seen \\\\Answered $Forwarded $MDNSent)"}]}})xxx"}
        )) {
            return false;
        }
         
        // Valid continuation response with base64 data (AUTHENTICATE)
        if (!test_json_output<imap::imap_responses>(
            datum{"+ YGgGCSqGSIb3EgECAgIAb1kwV6A=\r\n"},
            datum{R"xxx({"imap":{"responses":[{"type":"continuation","data":"YGgGCSqGSIb3EgECAgIAb1kwV6A="}]}})xxx"}
        )) {
            return false;
        }
        
        // Valid continuation response with UTF-8 text
        if (!test_json_output<imap::imap_responses>(
            datum{"+ Ready for additional command text\r\n"},
            datum{R"xxx({"imap":{"responses":[{"type":"continuation","data":"Ready for additional command text"}]}})xxx"}
        )) {
            return false;
        }
        
        // Continuation response with literal specification (for LOGIN/AUTHENTICATE)
        if (!test_json_output<imap::imap_responses>(
            datum{"+ \r\n"},
            datum{R"xxx({"imap":{"responses":[{"type":"continuation"}]}})xxx"}
        )) {
            return false;
        }
             
        // Invalid continuation response - invalid data (not base64 or UTF-8)
        if (!test_json_output<imap::imap_responses>(
            datum{"+ \xFF\xFE\xFD\xFC\xFB\xFA\r\n"},
            datum{"{}"}
        )) {
            return false;
        }
         
        // Continuation request with literal specification {16}
        if (!test_json_output<imap::imap_requests>(
            datum{"{16}\r\n"},
            datum{R"xxx({"imap":{"requests":[{"is_tagged":false,"type":"continuation","data":"{16}"}]}})xxx"}
        )) {
            return false;
        }
        
        // ================================================================
        // NEGATIVE TEST CASES
        // ================================================================
        
        // Multi-line with garbage on both lines
        if (!test_json_output<imap::imap_requests>(
            datum{"\x00\xFF\xFE\x01\x02garbage\r\n\x00\xFF\xFE\x01\x02garbage\r\n"},
            datum{"{}"}
        )) {
            return false;
        }
        
        // Missing CRLF terminator
        if (!test_json_output<imap::imap_requests>(
            datum{"a004 CAPABILITY"},
            datum{"{}"}
        )) {
            return false;
        }
        
        // Multiple junk lines with invalid commands
        if (!test_json_output<imap::imap_requests>(
            datum{"junk line one\r\njunk line two\r\n"},
            datum{"{}"}
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
