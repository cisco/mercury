///
/// \file fixed_datum.hpp
///
/// Fixed-size, non-owning views for protocol headers.
///
/// Copyright (c) 2025 Cisco Systems, Inc. All rights reserved.
/// License at https://github.com/cisco/mercury/blob/master/LICENSE
///

#ifndef FIXED_DATUM_HPP
#define FIXED_DATUM_HPP

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>

#include "datum.h"

/// \struct fixed_datum_field
///
/// Describes one field in a fixed-size, non-owning protocol-header view.
///
/// The field's position is determined by its order in the `fixed_datum` field
/// list.  `Tag` is an empty type used to name the field at compile time, and
/// `T` is the unsigned integer type used to read it.
///
/// \tparam Tag the compile-time name of the field
/// \tparam T the unsigned integer type of the field
///
/// \code{.cpp}
/// struct source_port {};
/// struct destination_port {};
/// using header = fixed_datum<4,
///     fixed_datum_field<source_port, uint16_t>,
///     fixed_datum_field<destination_port, uint16_t>>;
/// \endcode
///
template <typename Tag, typename T>
struct fixed_datum_field {
    using tag_type = Tag;
    using value_type = T;
};

/// Describes a sequence of bytes between fields in a fixed-datum layout.
///
/// Padding contributes to the layout's size and to the offsets of subsequent
/// fields, but does not create a named accessor.
///
/// \tparam N the number of padding bytes
///
template <size_t N>
struct fixed_datum_padding {
    static constexpr size_t size = N;
};

template <typename Element>
struct fixed_datum_element_size;

template <typename Tag, typename T>
struct fixed_datum_element_size<fixed_datum_field<Tag, T>>
    : std::integral_constant<size_t, sizeof(T)> { };

template <size_t N>
struct fixed_datum_element_size<fixed_datum_padding<N>>
    : std::integral_constant<size_t, N> { };

template <typename... Elements>
struct fixed_datum_layout_size
    : std::integral_constant<size_t,
          (size_t{0} + ... + fixed_datum_element_size<Elements>::value)> { };

template <typename>
inline constexpr bool fixed_datum_dependent_false = false;

template <typename WantedTag, size_t Offset, typename... Elements>
struct fixed_datum_field_info;

template <typename WantedTag, size_t Offset>
struct fixed_datum_field_info<WantedTag, Offset> {
    static_assert(fixed_datum_dependent_false<WantedTag>,
                  "fixed_datum field tag was not found");
};

template <typename WantedTag, size_t Offset, typename FieldTag, typename T,
          typename... Rest>
struct fixed_datum_field_info<
    WantedTag, Offset, fixed_datum_field<FieldTag, T>, Rest...>
    : fixed_datum_field_info<WantedTag, Offset + sizeof(T), Rest...> { };

template <typename WantedTag, size_t Offset, typename T, typename... Rest>
struct fixed_datum_field_info<
    WantedTag, Offset, fixed_datum_field<WantedTag, T>, Rest...> {
    using value_type = T;
    static constexpr size_t offset = Offset;
};

template <typename WantedTag, size_t Offset, size_t Padding,
          typename... Rest>
struct fixed_datum_field_info<
    WantedTag, Offset, fixed_datum_padding<Padding>, Rest...>
    : fixed_datum_field_info<WantedTag, Offset + Padding, Rest...> { };

/// \class fixed_datum
///
/// A nullable, fixed-size, non-owning view into a `datum`.
///
/// Construction from a `datum` performs one bounds check and consumes `N`
/// bytes on success.  If fewer than `N` bytes are available, both the view and
/// the input datum are set to null.
///
/// Unlike `datum`, this class stores only the start pointer; its extent is part
/// of its type.  A default-constructed view is null.  Test the view with its
/// boolean conversion before calling `read()` or `field()`.
///
/// Integer values are copied from the wire representation without byte-order
/// conversion.  This matches fields read from a packed network header; apply
/// `ntoh()` when a host-order value is required.
///
/// When field descriptors are supplied, `field<Tag>()` provides access without
/// repeating byte offsets in protocol code.  The descriptor list is checked
/// against `N` at compile time.
///
/// Example:
///
/// \code{.cpp}
/// namespace udp_fields {
/// struct source_port {};
/// struct destination_port {};
/// struct length {};
/// }
///
/// using udp_header = fixed_datum<6,
///     fixed_datum_field<udp_fields::source_port, uint16_t>,
///     fixed_datum_field<udp_fields::destination_port, uint16_t>,
///     fixed_datum_field<udp_fields::length, uint16_t>>;
///
/// datum input{packet, packet + packet_length};
/// udp_header header{input};
/// if (header) {
///     uint16_t source = ntoh(
///         header.field<udp_fields::source_port>());
///     uint16_t destination = ntoh(
///         header.field<udp_fields::destination_port>());
/// }
/// \endcode
///
/// The field list is ordered, so the example's fields occupy offsets 0, 2,
/// and 4.  Use `fixed_datum_padding<N>` to represent unmodeled bytes.
///
/// \tparam N the fixed extent of the view in bytes
/// \tparam Fields optional `fixed_datum_field` and `fixed_datum_padding`
/// descriptors, in wire order
///
template <size_t N, typename... Fields>
class fixed_datum {
    static_assert(sizeof...(Fields) == 0 ||
                  fixed_datum_layout_size<Fields...>::value == N,
                  "fixed_datum field layout does not match its extent");

    const unsigned char *data = nullptr;

    template <typename T>
    T read_unchecked(size_t offset) const noexcept {
        T value;
        memcpy(&value, data + offset, sizeof(value));
        return value;
    }

public:
    /// The fixed extent of this view in bytes.
    ///
    static constexpr size_t extent = N;

    /// Construct a null fixed datum.
    ///
    fixed_datum() = default;

    /// Construct a view by accepting exactly `N` bytes from `d`.
    ///
    /// If `d` does not contain `N` bytes, the view and `d` are set to null.
    /// On success, `d` is advanced by `N` bytes.
    ///
    /// \param d the input datum from which the fixed view is accepted
    ///
    explicit fixed_datum(datum &d) {
        if (!d.has_bytes(N)) {
            d.set_null();
            return;
        }
        data = d.data;
        d.data += N;
    }

    /// Test whether the view contains a valid fixed-size field.
    ///
    explicit operator bool() const noexcept { return data != nullptr; }

    /// Read an unsigned integer at a compile-time byte offset.
    ///
    /// The returned value has the wire/network byte-order representation.  Use
    /// `ntoh()` if a host-order value is needed.
    ///
    /// The offset and field size are checked at compile time.  The view must be
    /// valid before this function is called.
    ///
    /// \tparam T the unsigned integer type to read
    /// \tparam Offset the byte offset within the view
    ///
    /// \returns the field value in wire/network byte order
    ///
    /// \pre `*this` is valid
    ///
    template <typename T, size_t Offset>
    T read() const noexcept {
        static_assert(std::is_unsigned_v<T>, "fixed_datum fields must be unsigned");
        static_assert(Offset <= N && sizeof(T) <= N - Offset,
                      "fixed_datum read exceeds the view extent");
        assert(data != nullptr);
        return read_unchecked<T>(Offset);
    }

    /// Read a named field from the compile-time field layout.
    ///
    /// The field's offset is computed from the order of the field descriptors;
    /// protocol code does not need to repeat it.  The value is returned in
    /// wire/network byte order.  Use `ntoh()` if a host-order value is needed.
    ///
    /// \tparam Tag the tag used by the corresponding `fixed_datum_field`
    ///
    /// \returns the named field value in wire/network byte order
    ///
    /// \pre `*this` is valid
    ///
    template <typename Tag>
    typename fixed_datum_field_info<Tag, 0, Fields...>::value_type field() const noexcept {
        using info = fixed_datum_field_info<Tag, 0, Fields...>;
        using T = typename info::value_type;
        return read<T, info::offset>();
    }
};

#endif  // FIXED_DATUM_HPP
