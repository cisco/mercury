/*
 * metadata_writer.hpp
 *
 * Copyright (c) 2026 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef METADATA_WRITER_HPP
#define METADATA_WRITER_HPP

#include <type_traits>

/*
 * Shared helpers for feature visitors that serialize metadata through a
 * templated writer (json_object / cbor_object).  Library-only: these types are
 * used by the feature visitors in pkt_proc.cc and are NOT part of the CBOR
 * decoder that is mirrored into the mercury inspector.
 */

/// null_object is a "no-op" metadata writer that emits nothing.  It lets a
/// feature visitor run its assessment logic without producing any output,
/// while still being a concrete type (so it is deducible by CTAD and
/// selectable by `if constexpr`).  This replaces the older convention of
/// signalling "do not emit" with a null output pointer.
///
struct null_array { };
struct null_object { using array_type = null_array; };

/// is_emitting_writer<T> is true for writers that produce output, and false
/// for the null_object sentinel.  Feature visitors gate their emit paths on
/// is_emitting_writer_v<Object> so the null_object instantiation compiles to a
/// true no-op.
///
template <typename T> struct is_emitting_writer : std::true_type { };
template <> struct is_emitting_writer<null_object> : std::false_type { };

template <typename T>
constexpr bool is_emitting_writer_v = is_emitting_writer<T>::value;

/// has_array_type<T> detects whether T is a metadata writer, i.e. whether it
/// exposes a companion `array_type` member.  Modeled on has_write / has_write_v
/// in json_object.h.  Used to constrain feature-visitor Object parameters via
/// static_assert.
///
template <typename, typename = void>
struct has_array_type : std::false_type { };

template <typename T>
struct has_array_type<T, std::void_t<typename T::array_type>> : std::true_type { };

template <typename T>
constexpr bool has_array_type_v = has_array_type<T>::value;

#endif // METADATA_WRITER_HPP
