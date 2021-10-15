/*
 * proto_identify.h
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

/**
 * \file proto_identify.h
 *
 * \brief Protocol identification (header)
 */

#ifndef PROTO_IDENTIFY_H
#define PROTO_IDENTIFY_H

#include <stdint.h>
#include <vector>
#include <array>

enum tcp_msg_type {
    tcp_msg_type_unknown = 0,
    tcp_msg_type_http_request,
    tcp_msg_type_http_response,
    tcp_msg_type_tls_client_hello,
    tcp_msg_type_tls_server_hello,
    tcp_msg_type_tls_certificate,
    tcp_msg_type_ssh,
    tcp_msg_type_ssh_kex,
    tcp_msg_type_smtp_client,
    tcp_msg_type_smtp_server
};

enum udp_msg_type {
    udp_msg_type_unknown = 0,
    udp_msg_type_dns,
    udp_msg_type_dhcp,
    udp_msg_type_dtls_client_hello,
    udp_msg_type_dtls_server_hello,
    udp_msg_type_dtls_certificate,
    udp_msg_type_wireguard,
    udp_msg_type_quic,
    udp_msg_type_vxlan
};

template <size_t N>
class mask_and_value {
    uint8_t mask[N];
    uint8_t value[N];
public:
    constexpr mask_and_value(std::array<uint8_t, N> m, std::array<uint8_t, N> v) : mask{}, value{} {
        for (size_t i=0; i<N; i++) {
            mask[i] = m[i];
            value[i] = v[i];
        }
    }

    bool matches(const uint8_t tcp_data[N]) const {
        return u32_compare_masked_data_to_value(tcp_data, mask, value);  // TODO: verify that N=8
    }

    constexpr size_t length() const { return N; }

    static unsigned int u32_compare_masked_data_to_value(const void *data_in,
                                                         const void *mask_in,
                                                         const void *value_in) {
        const uint32_t *d = (const uint32_t *)data_in;
        const uint32_t *m = (const uint32_t *)mask_in;
        const uint32_t *v = (const uint32_t *)value_in;

        return ((d[0] & m[0]) == v[0]) && ((d[1] & m[1]) == v[1]);
    }

};

struct matcher_and_type {
    mask_and_value<8> mv;
    enum tcp_msg_type type;
};

class protocol_identifier {
    std::vector<matcher_and_type> a;

public:
    protocol_identifier() : a{} {  }

    void add_protocol(const mask_and_value<8> &mv, enum tcp_msg_type type) {
        struct matcher_and_type new_proto{mv, type};
        a.push_back(new_proto);
    }

    void compile() {
        // this function is a placeholder for now, but in the future,
        // it may compile a jump table, reorder matchers, etc.
    }

    enum tcp_msg_type get_msg_type(const uint8_t *data, unsigned int len) {
        if (len < 8) {
            return tcp_msg_type_unknown;
        }
        for (matcher_and_type p : a) {
            if (p.mv.matches(data)) {
                return p.type;
            }
        }
        return tcp_msg_type_unknown;
    }

};


/* Values indicating direction of the flow */
#define DIR_UNKNOWN 0
#define DIR_CLIENT 1
#define DIR_SERVER 2


/* destination port numbers for common protocols */

#define HTTP_PORT         80
#define HTTPS_PORT       443
#define SSH_PORT          22
#define SSH_KEX           23
#define SMTP_PORT         25
#define DHCP_CLIENT_PORT  67
#define DHCP_SERVER_PORT  68
#define DTLS_PORT         99
#define DNS_PORT          53
#define WIREGUARD_PORT 51820
#define QUIC_PORT       4433

#endif /* PROTO_IDENTIFY_H */
