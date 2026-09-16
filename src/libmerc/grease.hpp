// grease.hpp
//
// Copyright (c) 2026 Cisco Systems, Inc. All rights reserved. License at
// https://github.com/cisco/mercury/blob/master/LICENSE
//

#ifndef GREASE_HPP
#define GREASE_HPP

#include <cstdint>

// TLS GREASE values are defined by RFC 8701, "Applying Generate Random
// Extensions And Sustain Extensibility".
// https://www.rfc-editor.org/rfc/rfc8701

namespace grease {

/// \brief Test whether a 16-bit TLS value is a GREASE value.
///
constexpr bool is_grease_uint16(uint16_t x) {
    return (x & 0x0f) == 0x0a && (x >> 8) == (x & 0xff);
}

/// \brief Normalize a 16-bit TLS GREASE value.
///
constexpr uint16_t degrease_uint16(uint16_t x) {
    return is_grease_uint16(x) ? 0x0a0a : x;
}

/// \brief Test whether an 8-bit TLS value is a GREASE value.
///
constexpr bool is_grease_uint8(uint8_t x) {
    return x % 31 == 11;
}

/// \brief Normalize an 8-bit TLS GREASE value.
///
constexpr uint8_t degrease_uint8(uint8_t x) {
    return is_grease_uint8(x) ? 0x0b : x;
}

/// \brief Normalize a value using the TLS GREASE rule for its type.
///
/// Types without a TLS GREASE rule are returned unchanged.
///
template <typename T>
constexpr T normalize(T value) {
    return value;
}

template <>
constexpr uint16_t normalize<uint16_t>(uint16_t value) {
    return degrease_uint16(value);
}

template <>
constexpr uint8_t normalize<uint8_t>(uint8_t value) {
    return degrease_uint8(value);
}

#ifndef NDEBUG

// LCOV_EXCL_START
/// \brief Run unit tests for the TLS GREASE helpers.
///
/// \return true if all GREASE tests pass, and false otherwise
///
inline bool grease_unit_test() {
    for (unsigned value = 0x0a0a;
         value <= 0xfafa;
         value += 0x1010) {
        const uint16_t grease_value = static_cast<uint16_t>(value);
        if (!is_grease_uint16(grease_value) ||
            degrease_uint16(grease_value) != 0x0a0a ||
            normalize<uint16_t>(grease_value) != 0x0a0a) {
            return false;
        }
    }

    if (is_grease_uint16(0x0a1a) ||
        is_grease_uint16(0x1a0a) ||
        degrease_uint16(0x1234) != 0x1234 ||
        normalize<uint32_t>(0x12345678) != 0x12345678) {
        return false;
    }

    for (unsigned value = 0x0b; value <= 0xff; value += 31) {
        const uint8_t grease_value = static_cast<uint8_t>(value);
        if (!is_grease_uint8(grease_value) ||
            degrease_uint8(grease_value) != 0x0b ||
            normalize<uint8_t>(grease_value) != 0x0b) {
            return false;
        }
    }

    return !is_grease_uint8(0x0a) && !is_grease_uint8(0x0c);
}
// LCOV_EXCL_STOP
#endif // NDEBUG

} // namespace grease

#endif // GREASE_HPP
