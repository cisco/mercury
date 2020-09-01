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

struct ssh_init_packet {
    ssh_init_packet() { }
};

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
    struct parser kex_algorithms;
    struct parser server_host_key_algorithms;
    struct parser encryption_algorithms_client_to_server;
    struct parser encryption_algorithms_server_to_client;
    struct parser mac_algorithms_client_to_server;
    struct parser mac_algorithms_server_to_client;
    struct parser compression_algorithms_client_to_server;
    struct parser compression_algorithms_server_to_client;
    struct parser languages_client_to_server;
    struct parser languages_server_to_client;

    ssh_kex_init() :
        msg_type{NULL, NULL},
        cookie{NULL, NULL},
        kex_algorithms{NULL, NULL},
        server_host_key_algorithms{NULL, NULL},
        encryption_algorithms_client_to_server{NULL, NULL},
        encryption_algorithms_server_to_client{NULL, NULL},
        mac_algorithms_client_to_server{NULL, NULL},
        mac_algorithms_server_to_client{NULL, NULL},
        compression_algorithms_client_to_server{NULL, NULL},
        compression_algorithms_server_to_client{NULL, NULL},
        languages_client_to_server{NULL, NULL},
        languages_server_to_client{NULL, NULL} {
    }

    void parse(struct parser &p) {
        msg_type.parse(p, L_ssh_payload);
        cookie.parse(p, L_ssh_cookie);
        size_t tmp = 0;
        if (parser_read_and_skip_uint(&p, sizeof(uint32_t), &tmp) == status_err) {
            return;
        }
        kex_algorithms.parse(p, tmp);
        if (parser_read_and_skip_uint(&p, sizeof(uint32_t), &tmp) == status_err) {
            return;
        }
        server_host_key_algorithms.parse(p, tmp);
        if (parser_read_and_skip_uint(&p, sizeof(uint32_t), &tmp) == status_err) {
            return;
        }
        encryption_algorithms_client_to_server.parse(p, tmp);
        if (parser_read_and_skip_uint(&p, sizeof(uint32_t), &tmp) == status_err) {
            return;
        }
        encryption_algorithms_server_to_client.parse(p, tmp);
        if (parser_read_and_skip_uint(&p, sizeof(uint32_t), &tmp) == status_err) {
            return;
        }
        mac_algorithms_client_to_server.parse(p, tmp);
        if (parser_read_and_skip_uint(&p, sizeof(uint32_t), &tmp) == status_err) {
            return;
        }
        mac_algorithms_server_to_client.parse(p, tmp);
        if (parser_read_and_skip_uint(&p, sizeof(uint32_t), &tmp) == status_err) {
            return;
        }
        compression_algorithms_client_to_server.parse(p, tmp);
        if (parser_read_and_skip_uint(&p, sizeof(uint32_t), &tmp) == status_err) {
            return;
        }
        compression_algorithms_server_to_client.parse(p, tmp);
        if (parser_read_and_skip_uint(&p, sizeof(uint32_t), &tmp) == status_err) {
            return;
        }
        languages_client_to_server.parse(p, tmp);
        if (parser_read_and_skip_uint(&p, sizeof(uint32_t), &tmp) == status_err) {
            return;
        }
        languages_server_to_client.parse(p, tmp);
    }

    void write_json(json_object &o, bool output_metadata) {
        if (kex_algorithms.is_not_readable()) {
            return;
        }
        struct json_object ssh{o, "ssh"};
        struct json_object ssh_client{ssh, "client"};
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
        }
        ssh_client.close();
        ssh.close();
    }

};

#endif // SSH_H
