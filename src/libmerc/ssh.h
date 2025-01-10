
/*
 * ssh.h
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef SSH_H
#define SSH_H

#include <stdint.h>
#include <stdlib.h>
#include "protocol.h"
#include "datum.h"
#include "analysis.h"
#include "json_object.h"
#include "fingerprint.h"
#include "match.h"

// #define L_ssh_version_string                   8
// #define L_ssh_packet_length                    4
// #define L_ssh_padding_length                   1
// #define L_ssh_payload                          1
// #define L_ssh_cookie                          16
// #define L_ssh_kex_algo_len                     4
// #define L_ssh_server_host_key_algos_len        4
// #define L_ssh_enc_algos_client_to_server_len   4
// #define L_ssh_enc_algos_server_to_client_len   4
// #define L_ssh_mac_algos_client_to_server_len   4
// #define L_ssh_mac_algos_server_to_client_len   4
// #define L_ssh_comp_algos_client_to_server_len  4
// #define L_ssh_comp_algos_server_to_client_len  4
// #define L_ssh_languages_client_to_server_len   4
// #define L_ssh_languages_server_to_client_len   4


/*
 * From RFC 4253 (The SSH Transport Layer Protocol):
 *
 *    Each packet is in the following format:
 *
 *     uint32    packet_length (length of the packet in bytes, not
 *               including 'mac' or the 'packet_length' field itself.)
 *
 *     byte      padding_length (length of 'random padding' in bytes)
 *
 *     byte[n1]  payload; n1 = packet_length - padding_length - 1
 *
 *     byte[n2]  random padding; n2 = padding_length
 *
 *     byte[m]   mac (Message Authentication Code - MAC); m = mac_length
 *
 */
struct ssh_binary_packet {
    encoded<uint32_t> binary_packet_length;
    encoded<uint8_t> padding_length;
    struct datum payload;       // includes padding and MAC is present
    size_t additional_bytes_needed;
    struct datum trailing_data;     // data left after parsing a SSH binary pkt. Pass it on to kexinit pkt ctor
    // random padding
    // mac

    ssh_binary_packet(datum &p) : binary_packet_length{p}, padding_length{p}, payload{NULL, NULL}, additional_bytes_needed{0}, trailing_data{NULL, NULL} {
        parse(p);
    }

    ssh_binary_packet() : binary_packet_length{0}, padding_length{0} {}

    void parse(struct datum &p) {
        if (binary_packet_length > ssh_binary_packet::max_length || binary_packet_length < ssh_binary_packet::min_length) {
            p.set_empty();  // probably not a real SSH binary packet
            return;
        }
        if (!p.is_not_empty()) {
            return;
        }
        ssize_t bytes_left_in_binary_packet = binary_packet_length - 1;
        if (bytes_left_in_binary_packet > p.length()) {
            additional_bytes_needed = bytes_left_in_binary_packet - p.length();
            // fprintf(stderr, "ssh_binary_packet additional_bytes_needed: %zu (wanted: %zd, have: %zu)\n", additional_bytes_needed, bytes_left_in_packet, p.length());
        }
        payload.parse_soft_fail(p, bytes_left_in_binary_packet);
        
        // if trailing data, followup binary pkt
        if (p.is_not_empty()) {
            trailing_data = p;
        }
    }

    bool is_not_empty() {
        return payload.is_not_empty();
    }

    bool has_trailing_data() {
        return trailing_data.is_not_empty();
    }

    static const ssize_t max_length = 16384;
    static const ssize_t min_length = 1;
};

struct name_list : public datum {
    encoded<uint32_t> list_length;

    name_list() : datum{}, list_length{0} {}

    void parse(struct datum &p) {
        list_length = encoded<uint32_t>{p};
        if (list_length > name_list::max_length) {
            p.set_empty(); // packet is not really a KEX_INIT
            return;
        }
        datum::parse(p, list_length);
    }

    const static ssize_t max_length = 2048; // longest possible name
    // static constexpr uint32_t namelist_length_len = 4;
};

/*
 * Each session starts out with a KEXINIT message:
 *
 *     byte         SSH_MSG_KEXINIT
 *     byte[16]     cookie (random bytes)
 *     name-list    kex_algorithms
 *     name-list    server_host_key_algorithms
 *     name-list    encryption_algorithms_client_to_server
 *     name-list    encryption_algorithms_server_to_client
 *     name-list    mac_algorithms_client_to_server
 *     name-list    mac_algorithms_server_to_client
 *     name-list    compression_algorithms_client_to_server
 *     name-list    compression_algorithms_server_to_client
 *     name-list    languages_client_to_server
 *     name-list    languages_server_to_client
 *     boolean      first_kex_packet_follows
 *     uint32       0 (reserved for future extension)
 *
 */
// The kexinit pkt can hold one additional binary pkt if present in the same pkt. This can be
// used to parse the key exchange init of specific types like dhe init or kyber exchange.
//
struct ssh_kex_init : public base_protocol {
    struct datum msg_type;
    struct datum cookie;
    struct name_list kex_algorithms;
    struct name_list server_host_key_algorithms;
    struct name_list encryption_algorithms_client_to_server;
    struct name_list encryption_algorithms_server_to_client;
    struct name_list mac_algorithms_client_to_server;
    struct name_list mac_algorithms_server_to_client;
    struct name_list compression_algorithms_client_to_server;
    struct name_list compression_algorithms_server_to_client;
    struct name_list languages_client_to_server;
    struct name_list languages_server_to_client;
    bool secondary_binary_packet = false;
    ssh_binary_packet sec_pkt;

    static constexpr ssize_t ssh_msg_code_len = 1;
    static constexpr ssize_t ssh_cookie_len = 16;

    //ssh_kex_init(datum &p) { parse(p); };
    
    //ssh_kex_init(datum &p, datum trailing) { parse(p,trailing); };

    ssh_kex_init(ssh_binary_packet& pkt) {
        if (pkt.has_trailing_data()) {
            parse(pkt.payload,pkt.trailing_data);
        }
        else {
            parse(pkt.payload);
        }
    }

    ssh_kex_init() { };

    void parse(struct datum &p) {

        msg_type.parse(p, ssh_msg_code_len);
        cookie.parse(p, ssh_cookie_len);
        kex_algorithms.parse(p);
        server_host_key_algorithms.parse(p);
        encryption_algorithms_client_to_server.parse(p);
        encryption_algorithms_server_to_client.parse(p);
        mac_algorithms_client_to_server.parse(p);
        mac_algorithms_server_to_client.parse(p);
        compression_algorithms_client_to_server.parse(p);
        compression_algorithms_server_to_client.parse(p);
        languages_client_to_server.parse(p);
        languages_server_to_client.parse(p);
    }
    
    void parse(struct datum &p, datum trailing) {

        msg_type.parse(p, ssh_msg_code_len);
        cookie.parse(p, ssh_cookie_len);
        kex_algorithms.parse(p);
        server_host_key_algorithms.parse(p);
        encryption_algorithms_client_to_server.parse(p);
        encryption_algorithms_server_to_client.parse(p);
        mac_algorithms_client_to_server.parse(p);
        mac_algorithms_server_to_client.parse(p);
        compression_algorithms_client_to_server.parse(p);
        compression_algorithms_server_to_client.parse(p);
        languages_client_to_server.parse(p);
        languages_server_to_client.parse(p);
        sec_pkt = ssh_binary_packet{trailing};
        secondary_binary_packet = sec_pkt.is_not_empty();
    }

    bool is_not_empty() const { return kex_algorithms.is_not_empty(); }

    static inline void write_hex_data(buffer_stream &buf, const struct datum &d) {
        buf.write_char('(');
        if (d.is_not_empty()) {
            buf.raw_as_hex(d.data, d.length());
        }
        buf.write_char(')');
    }

    void fingerprint(struct buffer_stream &buf) const {
        if (kex_algorithms.is_not_readable()) {
            return;
        }
        write_hex_data(buf, kex_algorithms);
        write_hex_data(buf, server_host_key_algorithms);
        write_hex_data(buf, encryption_algorithms_client_to_server);
        write_hex_data(buf, encryption_algorithms_server_to_client);
        write_hex_data(buf, mac_algorithms_client_to_server);
        write_hex_data(buf, mac_algorithms_server_to_client);
        write_hex_data(buf, compression_algorithms_client_to_server);
        write_hex_data(buf, compression_algorithms_server_to_client);
        write_hex_data(buf, languages_client_to_server);
        write_hex_data(buf, languages_server_to_client);
        if (secondary_binary_packet) {
            buf.write_char('(');
            buf.write_hex_uint( (lookahead< encoded<uint8_t> >{sec_pkt.payload}).value);
            buf.write_hex_uint(sec_pkt.binary_packet_length);
            buf.write_char(')');
        }
    }

    void write_json_data(json_object &ssh_client) const {
        ssh_client.print_key_json_string("kex_algorithms", kex_algorithms.data, kex_algorithms.length());
        ssh_client.print_key_json_string("server_host_key_algorithms", server_host_key_algorithms.data, server_host_key_algorithms.length());
        ssh_client.print_key_json_string("encryption_algorithms_client_to_server", encryption_algorithms_client_to_server.data, encryption_algorithms_client_to_server.length());
        ssh_client.print_key_json_string("encryption_algorithms_server_to_client", encryption_algorithms_server_to_client.data, encryption_algorithms_server_to_client.length());
        ssh_client.print_key_json_string("mac_algorithms_client_to_server", mac_algorithms_client_to_server.data, mac_algorithms_client_to_server.length());
        ssh_client.print_key_json_string("mac_algorithms_server_to_client", mac_algorithms_server_to_client.data, mac_algorithms_server_to_client.length());
        ssh_client.print_key_json_string("compression_algorithms_client_to_server", compression_algorithms_client_to_server.data, compression_algorithms_client_to_server.length());
        ssh_client.print_key_json_string("compression_algorithms_server_to_client", compression_algorithms_server_to_client.data, compression_algorithms_server_to_client.length());
        ssh_client.print_key_json_string("languages_client_to_server", languages_client_to_server.data, languages_client_to_server.length());
        ssh_client.print_key_json_string("languages_server_to_client", languages_server_to_client.data, languages_server_to_client.length());
    }
    
    void write_json(json_object &o, bool output_metadata, bool nested = false) const {
        if (kex_algorithms.is_not_readable()) {
            return;
        }
        if (output_metadata) {
            if (!nested) {
                struct json_object ssh{o, "ssh"};
                struct json_object ssh_client{ssh, "kex"};
                write_json_data(ssh_client);
                ssh_client.close();
                if (secondary_binary_packet) {
                    ssh.print_key_int("sec_binary_pkt_code", (lookahead< encoded<uint8_t> >{sec_pkt.payload}).value);
                    ssh.print_key_int("sec_binary_pkt_len", sec_pkt.binary_packet_length);
                }
                ssh.close();
            }
            else {
                // ssh json object exists beforehand
                //
                struct json_object ssh_client{o, "kex"};
                write_json_data(ssh_client);
                ssh_client.close();
                if (secondary_binary_packet) {
                    o.print_key_int("sec_binary_pkt_code", (lookahead< encoded<uint8_t> >{sec_pkt.payload}).value);
                    o.print_key_int("sec_binary_pkt_len", sec_pkt.binary_packet_length);
                }
            }
        }
    }

    void compute_fingerprint(class fingerprint &fp) const {
        fp.set_type(fingerprint_type_ssh_kex);
        fp.add(*this);
        fp.final();
    }

    static constexpr mask_and_value<8> matcher{
        {
            0xff, 0xff, 0xf0, 0x00, // packet length
            0x00,                   // padding length
            0xff,                   // KEX code
            0x00, 0x00              // ...
        },
        {
            0x00, 0x00, 0x00, 0x00, // packet length
            0x00,                   // padding length
            0x14,                   // KEX code
            0x00, 0x00              // ...
        }
    };

};

/*
 *  Once the TCP connection has been established, both sides MUST send an
 *  identification string.  This identification string MUST be
 *
 *    SSH-protoversion-softwareversion SP comments CR LF
 *
 *  where 'protoversion' MUST be "2.0".  The 'comments' string is
 *  OPTIONAL.  If the 'comments' string is included, a 'space' character
 *  (denoted above as SP, ASCII 32) MUST separate the 'softwareversion'
 *  and 'comments' strings.  The identification MUST be terminated by a
 *  single Carriage Return (CR) and a single Line Feed (LF) character
 *  (ASCII 13 and 10, respectively).  Implementers who wish to maintain
 *  compatibility with older, undocumented versions of this protocol may
 *  want to process the identification string without expecting the
 *  presence of the carriage return character for reasons described in
 *  Section 5 of this document.  The null character MUST NOT be sent.
 *  The maximum length of the string is 255 characters, including the
 *  Carriage Return and Line Feed.
 */

// ssh init pkt can also hold an additional binary pkt to possibly parse the kex init pkt.


struct ssh_init_packet : public base_protocol {
    struct datum protocol_string;
    struct datum comment_string;
    ssh_binary_packet binary_pkt;
    ssh_kex_init kex_pkt;

    static constexpr size_t max_data_size = 8192;

    ssh_init_packet(datum &p) : protocol_string{NULL, NULL}, comment_string{NULL, NULL}, binary_pkt{}, kex_pkt{} {
        parse(p);
    }

    void parse(struct datum &p) {
        uint8_t delim = protocol_string.parse_up_to_delimiters(p, '\n', ' ');
        if (delim == '\n') {
            // no comment string
            p.skip(1);      // skip linefeed

            // check if more bytes are available
            // indicating that a kex pkt might be present
            //
            if (p.is_not_empty()) {
                binary_pkt = ssh_binary_packet{p};
                if (binary_pkt.is_not_empty()) {
                    kex_pkt = ssh_kex_init{binary_pkt};
                }
            }

            return;  // no comment string
        }
        
        p.skip(1);  // skip space
        comment_string.parse_up_to_delim(p, '\n');
        p.skip(1);  // skip linefeed

        // check if more bytes are available
        // indicating that a kex pkt might be present
        //
        if (p.is_not_empty()) {
            binary_pkt = ssh_binary_packet{p};
            if (binary_pkt.is_not_empty()) {
                kex_pkt = ssh_kex_init{binary_pkt};
            }
        }

        return;        
    }

    bool is_not_empty() {
        return protocol_string.is_not_empty();
    }

    void write_fingerprint_data(struct buffer_stream &buf) const {
        if (protocol_string.is_not_readable()) {
            return;
        }
        buf.write_char('(');
        struct datum tmp = protocol_string; // to avoid modifying object
        if (comment_string.is_not_empty()) {
            buf.raw_as_hex(tmp.data, tmp.data_end - tmp.data);
            buf.write_char('2');             // represent SP between protocol and comment strings
            buf.write_char('0');             // represent SP between protocol and comment strings
            tmp = comment_string;
            tmp.trim(1);                     // trim the trailing '\n'
            buf.raw_as_hex(tmp.data, tmp.data_end - tmp.data);
        } else {
            tmp.trim(1);                     // trim the trailing '\n'
            buf.raw_as_hex(tmp.data, tmp.data_end - tmp.data);
            //buf.write_char('2');             // represent SP between protocol and comment strings
            //buf.write_char('0');             // represent SP between protocol and comment strings
            //tmp = comment_string;
            //tmp.trim(1);
            //buf.raw_as_hex(tmp.data, tmp.data_end - tmp.data);
        }
        buf.write_char(')');
    }

    void fingerprint_complete(struct buffer_stream &buf) const {
        kex_pkt.fingerprint(buf);
    }
    
    void fingerprint(struct buffer_stream &buf) const {
        if (kex_pkt.is_not_empty()) {
            fingerprint_complete(buf);
        }
        else {
            write_fingerprint_data(buf);
        }
    }

    void compute_fingerprint(class fingerprint &fp) const {
        // depending on type of pkt, set correct fingerprint type
        if (kex_pkt.is_not_empty()){
            fp.set_type(fingerprint_type_ssh);
        }
        else {
            fp.set_type(fingerprint_type_ssh_init);
        }
        fp.add(*this);
        fp.final();
    }

    void write_json(json_object &o, bool output_metadata) {
        if (output_metadata == false) {
            return;
        }
        if (protocol_string.is_not_readable()) {
            return;
        }
        json_object json_ssh{o, "ssh"};
        json_object json_ssh_init{json_ssh, "init"};
        json_ssh_init.print_key_json_string("protocol", protocol_string.data, protocol_string.length());
        json_ssh_init.print_key_json_string("comment", comment_string.data, comment_string.length());
        json_ssh_init.close();

        if (kex_pkt.is_not_empty()) {
            kex_pkt.write_json(json_ssh, output_metadata, true);
        }

        json_ssh.close();

    }

    size_t more_bytes_needed() const {
        if (kex_pkt.is_not_empty()) {
            // check binary pkt for additional bytes
            return binary_pkt.additional_bytes_needed;
        }
        else {
            // unknown size, return max data size, denotes indefinite reassembly
            return max_data_size;
        }
    }

    static constexpr mask_and_value<8> matcher{
        { 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 },
        { 'S',  'S',  'H',  '-',  0x00, 0x00,  0x00, 0x00 }
    };

};

#endif // SSH_H
