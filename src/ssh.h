/*
 * ssh.h
 */

#ifndef SSH_H
#define SSH_H

#include <stdint.h>
#include <stdlib.h>
#include "mercury.h"
#include "parser.h"
#include "json_object.h"

#define L_ssh_version_string                   8
#define L_ssh_packet_length                    4
#define L_ssh_padding_length                   1
#define L_ssh_payload                          1
#define L_ssh_cookie                          16
#define L_ssh_kex_algo_len                     4
#define L_ssh_server_host_key_algos_len        4
#define L_ssh_enc_algos_client_to_server_len   4
#define L_ssh_enc_algos_server_to_client_len   4
#define L_ssh_mac_algos_client_to_server_len   4
#define L_ssh_mac_algos_server_to_client_len   4
#define L_ssh_comp_algos_client_to_server_len  4
#define L_ssh_comp_algos_server_to_client_len  4
#define L_ssh_languages_client_to_server_len   4
#define L_ssh_languages_server_to_client_len   4


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


// VERSLEN is the length of "SSH-2.0-"
//
#define VERS_LEN 8

struct ssh_init_packet {
    struct parser protocol_string;
    struct parser comment_string;

    ssh_init_packet() : protocol_string{NULL, NULL}, comment_string{NULL, NULL} { }

    void parse(struct parser &p) {
        uint8_t delim = protocol_string.parse_up_to_delimeters(p, '\n', ' ');
        if (delim == '\n') {
            return;  // no comment string
        }
        p.skip(1);
        comment_string.parse_up_to_delim(p, '\n');
        p.skip(1);
    }

    void fingerprint(json_object &o, const char *key) const {
        if (protocol_string.is_not_readable()) {
            return;
        }
        char fp_buffer[2048];
        struct buffer_stream buf(fp_buffer, sizeof(fp_buffer));

        buf.write_char('(');
        struct parser tmp = protocol_string; // to avoid modifying object
        tmp.skip(VERS_LEN);                  // advance over "SSH-2.0"
        if (comment_string.is_not_empty()) {
            buf.raw_as_hex(tmp.data, tmp.data_end - tmp.data);
            buf.write_char('2');             // represent SP between protocol and comment strings
            buf.write_char('0');             // represent SP between protocol and comment strings
            tmp = comment_string;
            tmp.trim(1);
            buf.raw_as_hex(tmp.data, tmp.data_end - tmp.data);
        } else {
            tmp.trim(1);                         // trim the trailing '\n'
            buf.raw_as_hex(tmp.data, tmp.data_end - tmp.data);
            buf.write_char('2');             // represent SP between protocol and comment strings
            buf.write_char('0');             // represent SP between protocol and comment strings
            tmp = comment_string;
            tmp.trim(1);
            buf.raw_as_hex(tmp.data, tmp.data_end - tmp.data);
        }
        buf.write_char(')');

        buf.write_char('\0'); // null-terminate the JSON string in the buffer
        o.print_key_string(key, fp_buffer);

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
        fingerprint(json_ssh_init, "fingerprint");
        json_ssh_init.close();
        json_ssh.close();
    }

};

/*
 * From RFC 4253 (The SSH Transport Layer Protocol):
 *
 *    Each packet is in the following format:
 *
 *     uint32    packet_length
 *     byte      padding_length
 *     byte[n1]  payload; n1 = packet_length - padding_length - 1
 *     byte[n2]  random padding; n2 = padding_length
 *     byte[m]   mac (Message Authentication Code - MAC); m = mac_length
 *
 */
struct ssh_binary_packet {
    uint32_t packet_length;
    uint8_t padding_length;
    struct parser payload;
    // random padding
    // mac

    ssh_binary_packet() : packet_length{0}, padding_length{0}, payload{NULL, NULL} {}

    void parse(struct parser &p) {
        p.read_uint32(&packet_length);
        p.read_uint8(&padding_length);
        payload.parse_soft_fail(p, packet_length - padding_length - 1);
    }
};

struct name_list : public parser {

    name_list() : parser{} {}

    void parse(struct parser &p) {
        uint32_t length;
        p.read_uint32(&length);
        parser::parse(p, length);
    }
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
struct ssh_kex_init {
    struct parser msg_type;
    struct parser cookie;
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

    ssh_kex_init() = default;
    // ssh_kex_init() :
    //     msg_type{NULL, NULL},
    //     cookie{NULL, NULL},
    //     kex_algorithms{NULL, NULL},
    //     server_host_key_algorithms{NULL, NULL},
    //     encryption_algorithms_client_to_server{NULL, NULL},
    //     encryption_algorithms_server_to_client{NULL, NULL},
    //     mac_algorithms_client_to_server{NULL, NULL},
    //     mac_algorithms_server_to_client{NULL, NULL},
    //     compression_algorithms_client_to_server{NULL, NULL},
    //     compression_algorithms_server_to_client{NULL, NULL},
    //     languages_client_to_server{NULL, NULL},
    //     languages_server_to_client{NULL, NULL} {
    // }

    void parse(struct parser &p) {
        msg_type.parse(p, L_ssh_payload);
        cookie.parse(p, L_ssh_cookie);
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

    static inline void write_hex_data(buffer_stream &buf, const struct parser &d) {
        buf.write_char('(');
        if (d.is_not_empty()) {
            buf.raw_as_hex(d.data, d.length());
        }
        buf.write_char(')');
    }

    void fingerprint(json_object &o, const char *key) const {
        if (kex_algorithms.is_not_readable()) {
            return;
        }
        char fp_buffer[8192];
        struct buffer_stream buf(fp_buffer, sizeof(fp_buffer));

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

        buf.write_char('\0'); // null-terminate the JSON string in the buffer
        o.print_key_string(key, fp_buffer);

    }

    void write_json(json_object &o, bool output_metadata) const {
        if (kex_algorithms.is_not_readable()) {
            return;
        }
        struct json_object ssh{o, "ssh"};
        struct json_object ssh_client{ssh, "kex"};
        if (output_metadata) {
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
            fingerprint(ssh_client, "fingerprint");
        }
        ssh_client.close();
        ssh.close();
    }

};

#endif // SSH_H
