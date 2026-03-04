#ifndef PROTOCOL_CONFIG_H
#define PROTOCOL_CONFIG_H

#include "global_config.h"
#include "tls.h"
#include "stun.h"
#include "bittorrent.h"
#include "smb2.h"
#include "ssdp.h"
#include "http.h"

/// Configure static protocol settings from global config.
///
/// Must be called once during initialization, before any
/// packet processors are created.
///
inline void configure_protocol_classes(const global_config &gc) {

    // raw features — unconditionally set every static member
    bool all_raw = gc.raw_features.at("all");

    tls_client_hello::set_raw_features(all_raw or gc.raw_features.at("tls"));
    stun::message::set_raw_features(all_raw or gc.raw_features.at("stun"));
    bittorrent_dht::set_raw_features(all_raw or gc.raw_features.at("bittorrent"));
    bittorrent_lsd::set_raw_features(all_raw or gc.raw_features.at("bittorrent"));
    bittorrent_handshake::set_raw_features(all_raw or gc.raw_features.at("bittorrent"));
    smb2_packet::set_raw_features(all_raw or gc.raw_features.at("smb"));
    ssdp::set_raw_features(all_raw or gc.raw_features.at("ssdp"));

    // http config
    http_config::set_http_headers(gc.http_headers.non_sensitive,
                                  gc.http_headers.all);
    http_config::set_http_body(gc.http_body_max);
}

#endif
