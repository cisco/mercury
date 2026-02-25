/*
 * telnet.hpp
 *
 * Copyright (c) 2026 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

/**
 * \file telnet.hpp
 *
 * \brief Telnet protocol parser (RFC 854/855)
 */

#ifndef TELNET_HPP
#define TELNET_HPP

#include <optional>
#include <cstdio>
#include <stddef.h>
#include <stdint.h>

#include "protocol.h"
#include "datum.h"
#include "lex.h"
#include "json_object.h"
#include "buffer_stream.h"

namespace telnet {

///
/// \brief Telnet message wrapper for Mercury protocol dispatch.
///
class message : public base_protocol {
    datum msg{};
    bool valid{false};

public:

    ///
    /// \brief Construct a message from an input datum.
    /// \param d Input/output datum cursor.
    ///
    message(datum &d);

    ///
    /// \brief Returns whether the message object is valid.
    /// \return True when construction succeeded.
    ///
    bool is_not_empty() const;

    ///
    /// \brief Serialize parsed Telnet items to JSON.
    /// \param record Destination JSON object.
    /// \param metadata Unused metadata flag.
    ///
    void write_json(json_object &record, bool metadata) const;

    ///
    /// \brief Serialize Telnet protocol presence to L7 metadata.
    /// \param o Destination CBOR object.
    /// \param metadata Unused metadata flag.
    ///
    void write_l7_metadata(cbor_object &o, bool metadata) const;
};

///
/// \brief Telnet command codes as defined by RFC 854.
///

enum class command : uint8_t {
    se = 240,    ///< End subnegotiation parameters
    nop = 241,   ///< No operation
    dm = 242,    ///< Data mark
    brk = 243,   ///< Break
    ip = 244,    ///< Interrupt process
    ao = 245,    ///< Abort output
    ayt = 246,   ///< Are you there
    ec = 247,    ///< Erase character
    el = 248,    ///< Erase line
    ga = 249,    ///< Go ahead
    sb = 250,    ///< Subnegotiation begin
    will = 251,  ///< WILL
    wont = 252,  ///< WONT
    do_cmd = 253,///< DO
    dont = 254,  ///< DONT
    iac = 255    ///< Interpret as command
};

///
/// \brief Telnet option codes (subset of IANA assignments).
///

enum class telnet_option : uint8_t {
    binary_transmission = 0,
    echo = 1,
    reconnection = 2,
    suppress_go_ahead = 3,
    approx_message_size_negotiation = 4,
    status = 5,
    timing_mark = 6,
    remote_controlled_trans_and_echo = 7,
    output_line_width = 8,
    output_page_size = 9,
    output_carriage_return_disposition = 10,
    output_horizontal_tab_stops = 11,
    output_horizontal_tab_disposition = 12,
    output_formfeed_disposition = 13,
    output_vertical_tabstops = 14,
    output_vertical_tab_disposition = 15,
    output_linefeed_disposition = 16,
    extended_ascii = 17,
    logout = 18,
    byte_macro = 19,
    data_entry_terminal = 20,
    supdup = 21,
    supdup_output = 22,
    send_location = 23,
    terminal_type = 24,
    end_of_record = 25,
    tacacs_user_identification = 26,
    output_marking = 27,
    terminal_location_number = 28,
    telnet_3270_regime = 29,
    x_3_pad = 30,
    negotiate_about_window_size = 31,
    terminal_speed = 32,
    remote_flow_control = 33,
    linemode = 34,
    x_display_location = 35,
    environment_option = 36,
    authentication_option = 37,
    encryption_option = 38,
    new_environment_option = 39,
    tn3270e = 40,
    xauth = 41,
    charset = 42,
    telnet_remote_serial_port_rsp = 43,
    com_port_control_option = 44,
    telnet_suppress_local_echo = 45,
    telnet_start_tls = 46,
    kermit = 47,
    send_url = 48,
    forward_x = 49,
    telopt_pragma_logon = 138,
    telopt_sspi_logon = 139,
    telopt_pragma_heartbeat = 140,
    extended_options_list = 255
};

///
/// \brief Byte value used to start a Telnet command sequence.
///

static constexpr uint8_t iac = static_cast<uint8_t>(command::iac);

///
///
/// \brief Parser for Telnet option/command objects beginning with IAC.
///
class option {
    command command_value{command::se};
    bool has_suboption{false};
    uint8_t suboption{0};
    datum option_data{};
    bool valid{false};

    static bool consume_byte(datum &cursor, uint8_t &value);
    static bool command_has_suboption(command cmd);
    static const char *command_name(command cmd);
    static const char *telnet_option_name(uint8_t option);
    static void print_suboption(json_object &cmd, uint8_t option);
    static bool parse_subnegotiation(datum &d, uint8_t &opt, datum &opt_data);

public:

    ///
    /// \brief Parse one Telnet command sequence from a datum.
    /// \param d Input/output datum cursor.
    ///
    option(datum &d);

    ///
    /// \brief Returns whether parsing succeeded.
    /// \return True if object contains a valid command.
    ///
    bool is_not_empty() const;

    ///
    /// \brief Serialize this command object as one item in a JSON array.
    /// \param items Destination JSON array.
    ///
    void write_json(json_array &items) const;
};

///
/// \brief Parser for contiguous Telnet data-byte sequences.
///
class data {
    datum bytes{};
    bool valid{false};

public:

    ///
    /// \brief Check whether the current cursor can be parsed as data.
    /// \param d Datum cursor snapshot.
    /// \return True if data parsing should be attempted first.
    ///
    static bool can_parse(datum d);

    ///
    /// \brief Parse one contiguous data segment (or escaped IAC) from a datum.
    /// \param d Input/output datum cursor.
    ///
    data(datum &d);

    ///
    /// \brief Returns whether parsing succeeded.
    /// \return True if object contains valid data bytes.
    ///
    bool is_not_empty() const;

    ///
    /// \brief Serialize this data segment as one item in a JSON array.
    /// \param items Destination JSON array.
    ///
    void write_json(json_array &items) const;
};

#ifndef NDEBUG

///
/// \brief Run Telnet parser unit tests.
/// \return True when all tests pass.
///
inline bool unit_test();

///
/// \brief Static test sentinel for debug builds.
///
static inline bool unit_test_passed = telnet::unit_test();
#endif

// ===== Definitions =====

inline bool option::consume_byte(datum &cursor, uint8_t &value) {
    encoded<uint8_t> byte{cursor};
    if (cursor.is_null()) {
        return false;
    }
    value = byte.value();
    return true;
}

inline bool option::command_has_suboption(command cmd) {
    return cmd == command::will || cmd == command::wont || cmd == command::do_cmd || cmd == command::dont || cmd == command::sb;
}

inline const char *option::command_name(command cmd) {
    switch (cmd) {
    case command::se: return "se";
    case command::nop: return "nop";
    case command::dm: return "dm";
    case command::brk: return "brk";
    case command::ip: return "ip";
    case command::ao: return "ao";
    case command::ayt: return "ayt";
    case command::ec: return "ec";
    case command::el: return "el";
    case command::ga: return "ga";
    case command::sb: return "sb";
    case command::will: return "will";
    case command::wont: return "wont";
    case command::do_cmd: return "do";
    case command::dont: return "dont";
    default: return "unknown";
    }
}

inline const char *option::telnet_option_name(uint8_t option_code) {
    // IANA Telnet Options registry (last updated 2022-03-16)
    // names normalized to lowercase_with_underscores
    switch (static_cast<telnet_option>(option_code)) {
    case telnet_option::binary_transmission: return "binary_transmission";
    case telnet_option::echo: return "echo";
    case telnet_option::reconnection: return "reconnection";
    case telnet_option::suppress_go_ahead: return "suppress_go_ahead";
    case telnet_option::approx_message_size_negotiation: return "approx_message_size_negotiation";
    case telnet_option::status: return "status";
    case telnet_option::timing_mark: return "timing_mark";
    case telnet_option::remote_controlled_trans_and_echo: return "remote_controlled_trans_and_echo";
    case telnet_option::output_line_width: return "output_line_width";
    case telnet_option::output_page_size: return "output_page_size";
    case telnet_option::output_carriage_return_disposition: return "output_carriage_return_disposition";
    case telnet_option::output_horizontal_tab_stops: return "output_horizontal_tab_stops";
    case telnet_option::output_horizontal_tab_disposition: return "output_horizontal_tab_disposition";
    case telnet_option::output_formfeed_disposition: return "output_formfeed_disposition";
    case telnet_option::output_vertical_tabstops: return "output_vertical_tabstops";
    case telnet_option::output_vertical_tab_disposition: return "output_vertical_tab_disposition";
    case telnet_option::output_linefeed_disposition: return "output_linefeed_disposition";
    case telnet_option::extended_ascii: return "extended_ascii";
    case telnet_option::logout: return "logout";
    case telnet_option::byte_macro: return "byte_macro";
    case telnet_option::data_entry_terminal: return "data_entry_terminal";
    case telnet_option::supdup: return "supdup";
    case telnet_option::supdup_output: return "supdup_output";
    case telnet_option::send_location: return "send_location";
    case telnet_option::terminal_type: return "terminal_type";
    case telnet_option::end_of_record: return "end_of_record";
    case telnet_option::tacacs_user_identification: return "tacacs_user_identification";
    case telnet_option::output_marking: return "output_marking";
    case telnet_option::terminal_location_number: return "terminal_location_number";
    case telnet_option::telnet_3270_regime: return "telnet_3270_regime";
    case telnet_option::x_3_pad: return "x_3_pad";
    case telnet_option::negotiate_about_window_size: return "negotiate_about_window_size";
    case telnet_option::terminal_speed: return "terminal_speed";
    case telnet_option::remote_flow_control: return "remote_flow_control";
    case telnet_option::linemode: return "linemode";
    case telnet_option::x_display_location: return "x_display_location";
    case telnet_option::environment_option: return "environment_option";
    case telnet_option::authentication_option: return "authentication_option";
    case telnet_option::encryption_option: return "encryption_option";
    case telnet_option::new_environment_option: return "new_environment_option";
    case telnet_option::tn3270e: return "tn3270e";
    case telnet_option::xauth: return "xauth";
    case telnet_option::charset: return "charset";
    case telnet_option::telnet_remote_serial_port_rsp: return "telnet_remote_serial_port_rsp";
    case telnet_option::com_port_control_option: return "com_port_control_option";
    case telnet_option::telnet_suppress_local_echo: return "telnet_suppress_local_echo";
    case telnet_option::telnet_start_tls: return "telnet_start_tls";
    case telnet_option::kermit: return "kermit";
    case telnet_option::send_url: return "send_url";
    case telnet_option::forward_x: return "forward_x";
    case telnet_option::telopt_pragma_logon: return "telopt_pragma_logon";
    case telnet_option::telopt_sspi_logon: return "telopt_sspi_logon";
    case telnet_option::telopt_pragma_heartbeat: return "telopt_pragma_heartbeat";
    case telnet_option::extended_options_list: return "extended_options_list";
    default:
        return nullptr;
    }
}

inline void option::print_suboption(json_object &cmd, uint8_t option_code) {
    if (const char *name = telnet_option_name(option_code)) {
        cmd.print_key_string("suboption", name);
        return;
    }

    output_buffer<48> unknown_name{};
    if ((option_code >= 50 && option_code <= 137) || (option_code >= 141 && option_code <= 254)) {
        unknown_name.snprintf("unassigned_%u", static_cast<unsigned>(option_code));
        cmd.print_key_string("suboption", unknown_name.get_buffer_start());
        return;
    }

    unknown_name.snprintf("unknown_%u", static_cast<unsigned>(option_code));
    cmd.print_key_string("suboption", unknown_name.get_buffer_start());
}

inline bool option::parse_subnegotiation(datum &d, uint8_t &opt, datum &opt_data) {
    if (!consume_byte(d, opt)) {
        return false;
    }

    datum payload_start{d};
    size_t payload_len = 0;

    while (d.is_not_empty()) {
        uint8_t byte = 0;
        if (!consume_byte(d, byte)) {
            return false;
        }
        if (byte != iac) {
            payload_len += 1;
            continue;
        }

        uint8_t next = 0;
        if (!consume_byte(d, next)) {
            return false;
        }
        if (next == iac) {
            payload_len += 2;
            continue; // escaped 0xff inside subnegotiation payload
        }
        if (next == static_cast<uint8_t>(command::se)) {
            opt_data = datum{payload_start, static_cast<ssize_t>(payload_len)};
            return opt_data.is_not_null();
        }

        payload_len += 2;
    }

    d.set_null();
    return false;
}

inline option::option(datum &d) : command_value{command::se}, has_suboption{false}, suboption{0}, option_data{}, valid{false} {
    if (!d.is_readable()) {
        d.set_null();
        return;
    }

    literal_byte<iac> prefix{d};
    if (d.is_null()) {
        return;
    }

    uint8_t parsed_command = 0;
    if (!consume_byte(d, parsed_command)) {
        return;
    }

    // Escaped IAC should be parsed as data, not option.
    if (parsed_command == iac) {
        d.set_null();
        return;
    }

    command cmd = static_cast<command>(parsed_command);
    command_value = cmd;

    if (cmd == command::sb) {
        if (!parse_subnegotiation(d, suboption, option_data)) {
            return;
        }
        has_suboption = true;
        valid = true;
        return;
    }

    if (command_has_suboption(cmd)) {
        if (!consume_byte(d, suboption)) {
            return;
        }
        has_suboption = true;
        valid = true;
        return;
    }

    valid = true;
}

inline bool option::is_not_empty() const {
    return valid;
}

inline void option::write_json(json_array &items) const {
    json_object item{items};
    item.print_key_string("command", command_name(command_value));
    if (has_suboption) {
        print_suboption(item, suboption);
    }
    if (option_data.is_not_empty()) {
        item.print_key_json_string("data", option_data);
    }
    item.close();
}

inline bool data::can_parse(datum d) {
    if (!d.is_readable()) {
        return false;
    }
    if (lookahead<literal_byte<iac, iac>> escaped{d}) {
        return true;
    }
    return !lookahead<literal_byte<iac>>{d};
}

inline data::data(datum &d) : bytes{}, valid{false} {
    if (!d.is_readable()) {
        d.set_null();
        return;
    }

    lookahead<literal_byte<iac>> iac_prefix{d};
    if (iac_prefix && !lookahead<literal_byte<iac, iac>>{d}) {
        d.set_null();
        return;
    }

    datum d_scan{d};
    escaped_string_up_to<iac, iac> parsed{d_scan};
    if (d_scan.is_null()) {
        bytes = d;
        d.set_empty();
        valid = bytes.is_not_empty();
        return;
    }

    bytes = datum{parsed.data, parsed.data_end};
    d.data = parsed.data_end;
    valid = bytes.is_not_empty();
}

inline bool data::is_not_empty() const {
    return valid;
}

inline void data::write_json(json_array &items) const {
    json_object item{items};
    item.print_key_json_string("data", bytes);
    item.close();
}

inline message::message(datum &d) : msg{}, valid{false} {
    if (!d.is_not_null()) {
        return;
    }
    msg = d;
    d.set_empty();
    valid = true;
}

inline bool message::is_not_empty() const {
    return valid;
}

inline void message::write_json(json_object &record, bool metadata) const {
    (void)metadata;

    if (!valid) {
        return;
    }

    bool truncated = false;
    datum d{msg};
    std::optional<json_object> telnet_object{};
    std::optional<json_array> message_items{};

    auto ensure_output = [&]() {
        if (!message_items) {
            telnet_object.emplace(record, "telnet");
            message_items.emplace(*telnet_object, "message");
        }
    };

    while (d.is_not_empty()) {
        if (data::can_parse(d)) {
            data bytes{d};
            if (!bytes.is_not_empty() || d.is_null()) {
                truncated = true;
                break;
            }
            ensure_output();
            bytes.write_json(*message_items);
        } else {
            option opt{d};
            if (!opt.is_not_empty() || d.is_null()) {
                truncated = true;
                break;
            }
            ensure_output();
            opt.write_json(*message_items);
        }
    }

    if (message_items) {
        message_items->close();
        if (truncated) {
            telnet_object->print_key_bool("truncated", true);
        }
        telnet_object->close();
    }
}

inline void message::write_l7_metadata(cbor_object &o, bool metadata) const {
    (void)metadata;

    if (!valid) {
        return;
    }

    cbor_array protocols{o, "protocols"};
    protocols.print_string("telnet");
    protocols.close();
}

#ifndef NDEBUG
inline bool unit_test() {
    auto check = [](datum input, datum expected) {
        if (test_json_output<telnet::message>(input, expected)) {
            return true;
        }
        std::fputs("telnet unit_test expected: ", stderr);
        if (expected.is_not_readable()) {
            std::fputs("<null>\n", stderr);
        } else {
            std::fwrite(expected.data, 1, static_cast<size_t>(expected.length()), stderr);
            std::fputc('\n', stderr);
        }
        std::fputs("telnet unit_test actual: ", stderr);
        (void)test_json_output<telnet::message>(input, expected, stderr);
        return false;
    };

    // "hi" + IAC WILL ECHO(1) + IAC DO SGA(3)
    const uint8_t negotiation_packet[] = {
        0x68, 0x69, 0xff, 0xfb, 0x01, 0xff, 0xfd, 0x03
    };

    if (!check(
        datum{negotiation_packet, negotiation_packet + sizeof(negotiation_packet)},
        datum{"{\"telnet\":{\"message\":[{\"data\":\"hi\"},{\"command\":\"will\",\"suboption\":\"echo\"},{\"command\":\"do\",\"suboption\":\"suppress_go_ahead\"}]}}"}
    )) {
        return false;
    }

    // IAC SB TTYPE(24) SEND(1) IAC SE
    const uint8_t subneg_packet[] = {
        0xff, 0xfa, 0x18, 0x01, 0xff, 0xf0
    };

    if (!check(
        datum{subneg_packet, subneg_packet + sizeof(subneg_packet)},
        datum{"{\"telnet\":{\"message\":[{\"command\":\"sb\",\"suboption\":\"terminal_type\",\"data\":\"\\u0001\"}]}}"}
    )) {
        return false;
    }

    // Interleaved data and command should preserve order.
    const uint8_t interleaved_packet[] = {
        'a', 0xff, 0xfd, 0x03, 'b'
    };

    if (!check(
        datum{interleaved_packet, interleaved_packet + sizeof(interleaved_packet)},
        datum{"{\"telnet\":{\"message\":[{\"data\":\"a\"},{\"command\":\"do\",\"suboption\":\"suppress_go_ahead\"},{\"data\":\"b\"}]}}"}
    )) {
        return false;
    }

    // Plain data should still be parseable on selected Telnet traffic.
    if (!check(
        datum{"login: root\r\n"},
        datum{"{\"telnet\":{\"message\":[{\"data\":\"login: root\\u000d\\u000a\"}]}}"}
    )) {
        return false;
    }

    // Escaped IAC (0xff 0xff) should be parsed as data, not command.
    const uint8_t escaped_iac_packet[] = {
        'x', 0xff, 0xff, 'y'
    };

    if (!check(
        datum{escaped_iac_packet, escaped_iac_packet + sizeof(escaped_iac_packet)},
        datum{"{\"telnet\":{\"message\":[{\"data\":\"x\\ufffd\"}]}}"}
    )) {
        return false;
    }

    return true;
}
#endif

} // namespace telnet

namespace {

///
/// \brief Fuzz harness entrypoint for Telnet message JSON output.
/// \param data Input bytes.
/// \param size Number of bytes.
/// \return Fuzzer status code.
///
inline int telnet_message_fuzz_test(const uint8_t *data_bytes, size_t size) {
    return json_output_fuzzer<telnet::message>(data_bytes, size);
}

} // namespace

#endif // TELNET_HPP
