///
/// \file packed_view.hpp
///
/// Fixed-size, non-owning views for protocol headers.
///
/// Copyright (c) 2025 Cisco Systems, Inc. All rights reserved.
/// License at https://github.com/cisco/mercury/blob/master/LICENSE
///

#ifndef PACKED_VIEW_HPP
#define PACKED_VIEW_HPP

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <type_traits>

#include "datum.h"

/// \struct packed_view_field
///
/// Describes one field in a fixed-size, non-owning protocol-header view.
///
/// The field's position is determined by its order in the `packed_view` field
/// list.  `Tag` is an empty type used to name the field at compile time, and
/// `T` is the unsigned integer type used to read it.
///
/// \tparam Tag the compile-time name of the field
/// \tparam T the unsigned integer type of the field
///
/// \code{.cpp}
/// struct source_port {};
/// struct destination_port {};
/// using header = packed_view<
///     packed_view_field<source_port, uint16_t>,
///     packed_view_field<destination_port, uint16_t>>;
/// \endcode
///
template <typename Tag, typename T>
struct packed_view_field {
    using tag_type = Tag;
    using value_type = T;
};

/// Describes a sequence of bytes between fields in a packed-view layout.
///
/// Padding contributes to the layout's size and to the offsets of subsequent
/// fields, but does not create a named accessor.
///
/// \tparam N the number of padding bytes
///
template <size_t N>
struct packed_view_padding {
    static constexpr size_t size = N;
};

template <typename Element>
struct packed_view_element_size;

template <typename Tag, typename T>
struct packed_view_element_size<packed_view_field<Tag, T>>
    : std::integral_constant<size_t, sizeof(T)> { };

template <size_t N>
struct packed_view_element_size<packed_view_padding<N>>
    : std::integral_constant<size_t, N> { };

/// Computes the total wire extent of a packed-view field layout.
///
/// The result is the sum of the sizes of all field and padding descriptors.
///
/// \tparam Elements the field and padding descriptors, in wire order
///
template <typename... Elements>
struct packed_view_layout_size
    : std::integral_constant<size_t,
          (size_t{0} + ... + packed_view_element_size<Elements>::value)> { };

/// Counts occurrences of a field tag in a packed-view layout.
///
/// \tparam WantedTag the field tag to count
/// \tparam Elements the field and padding descriptors, in wire order
///
template <typename WantedTag, typename... Elements>
struct packed_view_tag_count;

template <typename WantedTag>
struct packed_view_tag_count<WantedTag>
    : std::integral_constant<size_t, 0> { };

template <typename WantedTag, typename FieldTag, typename T,
          typename... Rest>
struct packed_view_tag_count<
    WantedTag, packed_view_field<FieldTag, T>, Rest...>
    : std::integral_constant<size_t,
          (std::is_same_v<WantedTag, FieldTag> ? 1 : 0) +
              packed_view_tag_count<WantedTag, Rest...>::value> { };

template <typename WantedTag, size_t Padding, typename... Rest>
struct packed_view_tag_count<
    WantedTag, packed_view_padding<Padding>, Rest...>
    : packed_view_tag_count<WantedTag, Rest...> { };

/// Tests whether all field tags in a packed-view layout are unique.
///
/// Padding descriptors are ignored.  A layout with duplicate field tags is
/// ambiguous because `field<Tag>()` would otherwise select the first match.
///
/// \tparam Elements the field and padding descriptors, in wire order
///
template <typename... Elements>
struct packed_view_tags_unique;

template <>
struct packed_view_tags_unique<> : std::true_type { };

template <typename FieldTag, typename T, typename... Rest>
struct packed_view_tags_unique<packed_view_field<FieldTag, T>, Rest...>
    : std::bool_constant<
          packed_view_tag_count<FieldTag, Rest...>::value == 0 &&
          packed_view_tags_unique<Rest...>::value> { };

template <size_t Padding, typename... Rest>
struct packed_view_tags_unique<packed_view_padding<Padding>, Rest...>
    : packed_view_tags_unique<Rest...> { };

template <typename>
inline constexpr bool packed_view_dependent_false = false;

template <typename WantedTag, size_t Offset, typename... Elements>
struct packed_view_field_info;

template <typename WantedTag, size_t Offset>
struct packed_view_field_info<WantedTag, Offset> {
    static_assert(packed_view_dependent_false<WantedTag>,
                  "packed_view field tag was not found");
};

template <typename WantedTag, size_t Offset, typename FieldTag, typename T,
          typename... Rest>
struct packed_view_field_info<
    WantedTag, Offset, packed_view_field<FieldTag, T>, Rest...>
    : packed_view_field_info<WantedTag, Offset + sizeof(T), Rest...> { };

template <typename WantedTag, size_t Offset, typename T, typename... Rest>
struct packed_view_field_info<
    WantedTag, Offset, packed_view_field<WantedTag, T>, Rest...> {
    using value_type = T;
    static constexpr size_t offset = Offset;
};

template <typename WantedTag, size_t Offset, size_t Padding,
          typename... Rest>
struct packed_view_field_info<
    WantedTag, Offset, packed_view_padding<Padding>, Rest...>
    : packed_view_field_info<WantedTag, Offset + Padding, Rest...> { };

/// \class packed_view
///
/// A nullable, fixed-size, non-owning view into a `datum`.
///
/// Construction from a `datum` performs one bounds check and consumes the
/// layout's computed extent on success.  If fewer bytes are available, both
/// the view and the input datum are set to null.
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
/// repeating byte offsets in protocol code.  The descriptor list determines
/// the view's extent at compile time, which is available as `extent`.
/// Field tags must be unique; duplicate tags produce a compile-time error.
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
/// using udp_header = packed_view<
///     packed_view_field<udp_fields::source_port, uint16_t>,
///     packed_view_field<udp_fields::destination_port, uint16_t>,
///     packed_view_field<udp_fields::length, uint16_t>>;
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
/// and 4, and the view's `extent` is 6.  Use `packed_view_padding<N>` to
/// represent unmodeled bytes.  The computed extent can be used in a compile-
/// time assertion, for example `static_assert(udp_header::extent == 6)`.
///
/// \tparam Fields optional `packed_view_field` and `packed_view_padding`
/// descriptors, in wire order
///
template <typename... Fields>
class packed_view {
    static_assert(packed_view_tags_unique<Fields...>::value,
                  "packed_view field tags must be unique");

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
    static constexpr size_t extent = packed_view_layout_size<Fields...>::value;

    /// Construct a null packed view.
    ///
    packed_view() = default;

    /// Construct a view by accepting exactly `extent` bytes from `d`.
    ///
    /// If `d` does not contain `extent` bytes, the view and `d` are set to
    /// null.  On success, `d` is advanced by `extent` bytes.
    ///
    /// \param d the input datum from which the fixed view is accepted
    ///
    explicit packed_view(datum &d) {
        if (!d.has_bytes(extent)) {
            d.set_null();
            return;
        }
        data = d.data;
        d.data += extent;
    }

    /// Test whether the view contains a valid fixed-size field.
    ///
    explicit operator bool() const noexcept { return data != nullptr; }

    /// Read an unsigned integer at a compile-time byte offset.
    ///
    /// The returned value has the wire/network byte-order representation.  Use
    /// `ntoh()` if a host-order value is needed.
    ///
    /// The offset and field size are checked at compile time.  This function
    /// must only be called after `operator bool()` returns true.
    ///
    /// \tparam T the unsigned integer type to read
    /// \tparam Offset the byte offset within the view
    ///
    /// \returns the field value in wire/network byte order
    ///
    /// \pre `data != nullptr`; this precondition is not checked in release
    /// builds.
    ///
    template <typename T, size_t Offset>
    T read() const noexcept {
        static_assert(std::is_unsigned_v<T> && !std::is_same_v<std::remove_cv_t<T>, bool>
                      && !std::is_same_v<std::remove_cv_t<T>, char>,
                      "packed_view fields must be unsigned integers (not char or bool)");
        static_assert(Offset <= extent && sizeof(T) <= extent - Offset,
                      "packed_view read exceeds the view extent");
        assert(data != nullptr);
        return read_unchecked<T>(Offset);
    }

    /// Read a named field from the compile-time field layout.
    ///
    /// The field's offset is computed from the order of the field descriptors;
    /// protocol code does not need to repeat it.  The value is returned in
    /// wire/network byte order.  Use `ntoh()` if a host-order value is needed.
    ///
    /// \tparam Tag the tag used by the corresponding `packed_view_field`
    ///
    /// \returns the named field value in wire/network byte order
    ///
    /// \pre `*this` is valid
    ///
    template <typename Tag>
    typename packed_view_field_info<Tag, 0, Fields...>::value_type field() const noexcept {
        using info = packed_view_field_info<Tag, 0, Fields...>;
        using T = typename info::value_type;
        return read<T, info::offset>();
    }
};

#endif  // PACKED_VIEW_HPP
