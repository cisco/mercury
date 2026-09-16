// variable_length_vector.hpp
//
// Copyright (c) 2026 Cisco Systems, Inc. All rights reserved. License at
// https://github.com/cisco/mercury/blob/master/LICENSE
//

#ifndef VARIABLE_LENGTH_VECTOR_HPP
#define VARIABLE_LENGTH_VECTOR_HPP

#include "datum.h"
#include "grease.hpp"
#include "parsed_extent.hpp"

#include <cstdint>
#include <cstring>
#include <optional>
#include <type_traits>

/// \struct no_length
///
/// Tag type used by variable_length_vector for vectors without a length field.
///
struct no_length { };

namespace variable_length_vector_detail {

template <typename T>
struct is_supported_type : std::bool_constant<
    std::is_same_v<T, uint8_t> ||
    std::is_same_v<T, uint16_t> ||
    std::is_same_v<T, uint32_t> ||
    std::is_same_v<T, uint64_t>> { };

template <typename T>
class length_field {
    encoded<T> value;

public:

    /// \brief Parse a fixed-width length field from \p d.
    ///
    /// \param d input datum
    ///
    explicit length_field(datum &d) : value{d} { }

    /// \brief Return the parsed length.
    ///
    /// \param d unused input datum
    /// \return parsed length in bytes
    ///
    size_t length(const datum &) const {
        return static_cast<size_t>(value.value());
    }
};

template <>
class length_field<no_length> {
public:

    /// \brief Construct a length-field parser for a vector without a prefix.
    ///
    /// \param d input datum
    ///
    explicit length_field(datum &) { }

    /// \brief Return the number of bytes remaining in \p d.
    ///
    /// \param d input datum
    /// \return remaining length in bytes
    ///
    size_t length(const datum &d) const {
        return static_cast<size_t>(d.length());
    }
};

} // namespace variable_length_vector_detail

/// \brief A non-owning, composable parser for a vector of encoded values.
///
/// The vector is either preceded by a fixed-width byte length field, or, when
/// LengthT is no_length, consumes all bytes remaining in the input datum.
/// Values retain their network-byte-order representation and may be accessed
/// safely even when the input address is not aligned for T.
///
/// \tparam T element type
/// \tparam LengthT unsigned type of the byte length field, or no_length
///
template <typename T, typename LengthT = no_length>
class variable_length_vector {
    static_assert(variable_length_vector_detail::is_supported_type<T>::value);
    static_assert(std::is_same_v<LengthT, no_length> ||
                  variable_length_vector_detail::is_supported_type<LengthT>::value);

    /// \brief Validate and retain the vector elements from \p d.
    ///
    /// \param d input datum
    /// \param length number of element bytes
    /// \return pointer to the elements, or nullptr if invalid
    ///
    static const uint8_t *parse_elements(datum &d, size_t length) {
        if (length % sizeof(T) != 0 || !d.has_bytes(length)) {
            d.set_null();
            return nullptr;
        }

        const uint8_t *result = d.data;
        d.data += length;
        return result;
    }

    variable_length_vector_detail::length_field<LengthT> length_field;
    size_t length_value;
    const uint8_t *elements;

public:

    /// \brief Parse a vector from \p d.
    ///
    /// The input datum is advanced past the length field and vector. It is
    /// set to null if the vector is truncated or is not an integral number
    /// of T-sized elements.
    ///
    /// \param d input datum
    ///
    variable_length_vector(datum &d)
        : length_field{d},
          length_value{length_field.length(d)},
          elements{parse_elements(d, length_value)} { }

    /// \brief Test whether parsing produced a non-null vector.
    ///
    /// \return true if the vector is valid, and false otherwise
    ///
    bool is_not_null() const {
        return elements != nullptr;
    }

    /// \brief Test whether parsing produced a valid vector.
    ///
    /// A valid empty vector also returns true.  Accessors for vector elements
    /// require a successful construction and a valid element index.
    ///
    /// \return true if the vector is valid, and false otherwise
    ///
    explicit operator bool() const {
        return is_not_null();
    }

    /// \brief Test whether the valid vector contains no elements.
    ///
    /// \return true if the vector is valid and empty, and false otherwise
    ///
    bool is_empty() const {
        return is_not_null() && length_value == 0;
    }

    /// \brief Return the vector length in bytes.
    ///
    /// \pre the vector was constructed successfully
    /// \return vector length in bytes
    ///
    size_t length() const {
        return length_value;
    }

    /// \brief Return the number of elements in the vector.
    ///
    /// \pre the vector was constructed successfully
    /// \return number of elements
    ///
    size_t size() const {
        return is_not_null() ? length_value / sizeof(T) : 0;
    }

    /// \brief Return the element at \p index.
    ///
    /// \param index element index
    /// \pre the vector was constructed successfully
    /// \pre \p index is less than size()
    /// \return element copied from the input without byte-order conversion
    ///
    T operator[](size_t index) const {
        T value{};
        std::memcpy(&value, elements + index * sizeof(T), sizeof(value));
        return value;
    }

    /// \brief Return the element at \p index, if present.
    ///
    /// \param index element index
    /// \pre the vector was constructed successfully
    /// \return element copied from the input without byte-order conversion,
    /// or nullopt when out of bounds
    ///
    std::optional<T> at(size_t index) const {
        if (index >= size()) {
            return std::nullopt;
        }

        return (*this)[index];
    }

    /// \brief Compare vectors after normalizing each element.
    ///
    /// Elements retain their network-byte-order representation, and the
    /// normalized elements are compared bytewise.  The explicit byte length
    /// is compared before the normalized elements.
    ///
    /// The caller must use parsed_extent when invalid values or trailing input
    /// must participate in comparison.
    ///
    /// \param other vector to compare
    /// \pre both vectors were constructed successfully
    /// \return a negative, zero, or positive comparison result
    ///
    int compare_degreased(const variable_length_vector &other) const {
        if (length_value != other.length_value) {
            return length_value < other.length_value ? -1 : 1;
        }

        for (size_t i = 0; i < size(); ++i) {
            T a_value = grease::normalize<T>((*this)[i]);
            T b_value = grease::normalize<T>(other[i]);
            int comparison = std::memcmp(&a_value, &b_value, sizeof(T));
            if (comparison != 0) {
                return comparison < 0 ? -1 : 1;
            }
        }

        return 0;
    }
};

// Unit tests, available when NDEBUG is not defined.
//
#ifndef NDEBUG

// LCOV_EXCL_START
/// \brief Run unit tests for variable_length_vector.
///
/// \return true if all tests pass, and false otherwise
///
inline bool variable_length_vector_unit_test() {
    static constexpr uint8_t explicit_length_data[] = {
        0xff, 0x00, 0x04, 0x1a, 0x1a, 0x12, 0x34, 0xee
    };
    datum explicit_input{explicit_length_data + 1,
                         explicit_length_data + sizeof(explicit_length_data)};
    variable_length_vector<uint16_t, uint16_t> explicit_values{explicit_input};
    if (!explicit_values || !explicit_values.is_not_null() ||
        explicit_values.is_empty() || explicit_values.length() != 4 ||
        explicit_values.size() != 2 || explicit_input.length() != 1) {
        return false;
    }
    std::optional<uint16_t> checked_first = explicit_values.at(0);
    uint16_t first_value = explicit_values[0];
    uint16_t second_value = explicit_values[1];
    if (!checked_first ||
        std::memcmp(&*checked_first, explicit_length_data + 3, sizeof(uint16_t)) ||
        std::memcmp(&first_value, explicit_length_data + 3, sizeof(first_value)) ||
        std::memcmp(&second_value, explicit_length_data + 5, sizeof(second_value)) ||
        explicit_values.at(2)) {
        return false;
    }

    static constexpr uint8_t normalized_data[] = {
        0x00, 0x02, 0x0a, 0x0a
    };
    datum normalized_input{normalized_data,
                           normalized_data + sizeof(normalized_data)};
    variable_length_vector<uint16_t, uint16_t> normalized_values{normalized_input};

    static constexpr uint8_t greased_data[] = {
        0x00, 0x02, 0x1a, 0x1a
    };
    datum greased_input{greased_data, greased_data + sizeof(greased_data)};
    variable_length_vector<uint16_t, uint16_t> greased_values{greased_input};

    static constexpr uint8_t greater_data[] = {
        0x00, 0x02, 0x10, 0x00
    };
    datum greater_input{greater_data, greater_data + sizeof(greater_data)};
    variable_length_vector<uint16_t, uint16_t> greater_values{greater_input};

    if (!normalized_values || !greased_values || !greater_values ||
        greased_values.compare_degreased(normalized_values) != 0 ||
        greased_values.compare_degreased(greater_values) >= 0 ||
        greater_values.compare_degreased(greased_values) <= 0) {
        return false;
    }

    static constexpr uint8_t no_length_data[] = {
        0x1a, 0x1a, 0x12, 0x34
    };
    datum no_length_input{no_length_data,
                          no_length_data + sizeof(no_length_data)};
    variable_length_vector<uint16_t, no_length> no_length_values{no_length_input};
    if (!no_length_values || !no_length_values.is_not_null() ||
        no_length_values.is_empty() || no_length_values.length() != 4 ||
        no_length_values.size() != 2 || !no_length_input.is_empty()) {
        return false;
    }

    static constexpr uint8_t empty_data[] = { 0x00, 0x00, 0xee };
    datum empty_input{empty_data, empty_data + sizeof(empty_data)};
    variable_length_vector<uint16_t, uint16_t> empty_values{empty_input};
    if (!empty_values || !empty_values.is_not_null() ||
        !empty_values.is_empty() || empty_values.length() != 0 ||
        empty_values.size() != 0 || empty_values.at(0) ||
        empty_input.length() != 1) {
        return false;
    }

    static constexpr uint8_t truncated_data[] = { 0x00, 0x04, 0x1a };
    datum truncated_input{truncated_data,
                          truncated_data + sizeof(truncated_data)};
    variable_length_vector<uint16_t, uint16_t> truncated_values{truncated_input};
    if (truncated_values || truncated_values.is_not_null() ||
        !truncated_input.is_null()) {
        return false;
    }

    static constexpr uint8_t non_integral_data[] = {
        0x00, 0x03, 0x01, 0x02, 0x03
    };
    datum non_integral_input{non_integral_data,
                             non_integral_data + sizeof(non_integral_data)};
    variable_length_vector<uint16_t, uint16_t> non_integral_values{non_integral_input};
    if (non_integral_values || non_integral_values.is_not_null() ||
        !non_integral_input.is_null()) {
        return false;
    }

    // Equal normalized elements compare their remaining raw trailers.
    static constexpr uint8_t trailer_a_data[] = {
        0x00, 0x02, 0x1a, 0x1a, 0xee
    };
    static constexpr uint8_t trailer_b_data[] = {
        0x00, 0x02, 0x0a, 0x0a, 0xef
    };
    datum trailer_a_input{trailer_a_data};
    datum trailer_b_input{trailer_b_data};
    parsed_extent<variable_length_vector<uint16_t, uint16_t>> trailer_a{
        trailer_a_input
    };
    parsed_extent<variable_length_vector<uint16_t, uint16_t>> trailer_b{
        trailer_b_input
    };
    if (trailer_a.get_trailer().cmp(datum{trailer_a_data + 4,
                                          trailer_a_data + 5}) != 0 ||
        trailer_a.get_raw().cmp(datum{trailer_a_data}) != 0 ||
        trailer_a.get_parsed_data().cmp(datum{trailer_a_data,
                                              trailer_a_data + 4}) != 0 ||
        trailer_a.compare(trailer_b) >= 0 ||
        trailer_b.compare(trailer_a) <= 0) {
        return false;
    }

    // Invalid vectors sort before valid vectors.
    datum truncated_compare_input{truncated_data};
    datum normalized_compare_input{normalized_data};
    parsed_extent<variable_length_vector<uint16_t, uint16_t>> truncated_value{
        truncated_compare_input
    };
    parsed_extent<variable_length_vector<uint16_t, uint16_t>> normalized_value{
        normalized_compare_input
    };
    if (truncated_value.compare(normalized_value) >= 0 ||
        normalized_value.compare(truncated_value) <= 0) {
        return false;
    }

    // Two invalid vectors retain raw-byte ordering.
    static constexpr uint8_t other_truncated_data[] = {
        0x00, 0x04, 0x1b
    };
    datum other_truncated_input{other_truncated_data};
    parsed_extent<variable_length_vector<uint16_t, uint16_t>> other_truncated_value{
        other_truncated_input
    };
    if (truncated_value.compare(other_truncated_value) >= 0 ||
        other_truncated_value.compare(truncated_value) <= 0) {
        return false;
    }

    return true;
}
// LCOV_EXCL_STOP
#endif // NDEBUG

#endif // VARIABLE_LENGTH_VECTOR_HPP
