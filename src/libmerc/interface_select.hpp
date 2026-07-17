/*
 * interface_select.hpp
 *
 * Linux network interface auto-selection for mercury capture mode
 *
 * Copyright (c) 2026 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef INTERFACE_SELECT_HPP
#define INTERFACE_SELECT_HPP

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

namespace interface_select {

/// size (including the terminating NUL) of a buffer large enough to hold
/// any capture interface name across all supported platforms
///
static constexpr size_t INTERFACE_NAME_MAX = 16;

} // namespace interface_select

#ifdef __linux__

#include <ifaddrs.h>
#include <linux/if.h>
#include <linux/if_link.h>
#include <sys/socket.h>

namespace interface_select {

static_assert(INTERFACE_NAME_MAX >= IFNAMSIZ,
              "INTERFACE_NAME_MAX must be large enough to hold a Linux interface name");

struct interface_candidate {
    char name[INTERFACE_NAME_MAX];
    uint64_t rx_packets;
    double rx_ratio;
    unsigned int flags;
    bool has_stats;
};

static inline bool candidate_is_usable(const interface_candidate &candidate) {
    if ((candidate.flags & IFF_UP) == 0) {
        return false;
    }
    if (candidate.flags & IFF_LOOPBACK) {
        return false;
    }
    return true;
}

static inline bool candidate_is_better(const interface_candidate &candidate,
                                       const interface_candidate &best) {
    const bool candidate_running = (candidate.flags & IFF_RUNNING) != 0;
    const bool best_running = (best.flags & IFF_RUNNING) != 0;
    if (candidate_running != best_running) {
        return candidate_running;
    }

    const bool candidate_lower_up = (candidate.flags & IFF_LOWER_UP) != 0;
    const bool best_lower_up = (best.flags & IFF_LOWER_UP) != 0;
    if (candidate_lower_up != best_lower_up) {
        return candidate_lower_up;
    }

    if (candidate.has_stats != best.has_stats) {
        return candidate.has_stats;
    }

    if (candidate.rx_packets != best.rx_packets) {
        return candidate.rx_packets > best.rx_packets;
    }

    if (candidate.rx_ratio != best.rx_ratio) {
        return candidate.rx_ratio > best.rx_ratio;
    }

    return strcmp(candidate.name, best.name) < 0;
}

/// auto-detects a capture interface and writes its name into the buffer
/// \p name of length \p name_len
///
/// \return 0 on success, or non-zero on failure (reported on stderr)
///
static inline int detect_capture_interface(char *name, size_t name_len) {
    if (name == nullptr || name_len == 0) {
        return 1;
    }

    struct ifaddrs *head_ifaddr = nullptr;
    if (getifaddrs(&head_ifaddr) == -1) {
        perror("getifaddrs");
        return 1;
    }

    interface_candidate best = {};
    bool found = false;
    char last_name[INTERFACE_NAME_MAX] = { 0 };

    for (struct ifaddrs *ifa = head_ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr || ifa->ifa_name == nullptr) {
            continue;
        }
        if (ifa->ifa_addr->sa_family != AF_PACKET) {
            continue;
        }
        if (strcmp(last_name, ifa->ifa_name) == 0) {
            continue;
        }
        strncpy(last_name, ifa->ifa_name, sizeof(last_name) - 1);
        last_name[sizeof(last_name) - 1] = '\0';

        interface_candidate candidate = {};
        strncpy(candidate.name, ifa->ifa_name, sizeof(candidate.name) - 1);
        candidate.name[sizeof(candidate.name) - 1] = '\0';
        candidate.flags = ifa->ifa_flags;
        candidate.has_stats = ifa->ifa_data != nullptr;

        if (candidate.has_stats) {
            auto *stats = reinterpret_cast<struct rtnl_link_stats *>(ifa->ifa_data);
            candidate.rx_packets = stats->rx_packets;
            const uint64_t total_packets = static_cast<uint64_t>(stats->rx_packets) +
                                           static_cast<uint64_t>(stats->tx_packets);
            if (total_packets > 0) {
                candidate.rx_ratio = static_cast<double>(stats->rx_packets) /
                                     static_cast<double>(total_packets);
            }
        }

        if (!candidate_is_usable(candidate)) {
            continue;
        }

        if (!found || candidate_is_better(candidate, best)) {
            best = candidate;
            found = true;
        }
    }

    freeifaddrs(head_ifaddr);

    if (!found) {
        fprintf(stderr, "error: could not auto-detect a usable capture interface\n");
        return 1;
    }

    if (strlen(best.name) + 1 > name_len) {
        fprintf(stderr, "error: auto-detected interface name does not fit in the supplied buffer\n");
        return 1;
    }
    memcpy(name, best.name, strlen(best.name) + 1);

    return 0;
}

} // namespace interface_select

#else

namespace interface_select {

static inline int detect_capture_interface(char *name, size_t name_len) {
    (void)name;
    (void)name_len;
    fprintf(stderr, "error: capture interface auto-detection is not supported on this platform\n");
    return 1;
}

} // namespace interface_select

#endif

#endif /* INTERFACE_SELECT_HPP */
