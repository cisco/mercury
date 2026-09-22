// parsed_extent.hpp
//
// Copyright (c) 2026 Cisco Systems, Inc. All rights reserved. License at
// https://github.com/cisco/mercury/blob/master/LICENSE
//

#ifndef PARSED_EXTENT_HPP
#define PARSED_EXTENT_HPP

#include "datum.h"

#include <cassert>

/// \brief A parsed value together with its original extent and trailer.
///
/// This class provides a common boundary for comparing and emitting parsed
/// protocol data. The parser interprets the beginning of an input datum, but
/// the complete input must still be accounted for when the parsed value has
/// trailing bytes or when parsing fails. The original input is retained for
/// failed parses, and the unconsumed input is retained as a trailer for
/// successful parses.
///
/// Comparison delegates normalization and parsed-token ordering to Parser's
/// compare_degreased() member. If both normalized parsed values compare equal,
/// their trailers are compared as raw bytes. Output uses the same boundaries:
/// the caller emits the parsed value, including any normalization, and this
/// class emits the original trailer unchanged. A failed parse is both ordered
/// and emitted as its original input.
///
/// Parser must be constructible from datum& and provide is_not_null() and
/// compare_degreased(const Parser &). The parser is given the input datum
/// after raw has retained its initial extent; trailer then retains the
/// remaining input after parsing.
///
/// \tparam Parser composable parser type
///
template <typename Parser>
class parsed_extent {
    datum raw;
    Parser value;
    datum trailer;

public:

    /// \brief Parse a value and retain its input extent.
    ///
    /// \param d input datum
    ///
    explicit parsed_extent(datum &d)
        : raw{d},
          value{d},
          trailer{d} { }

    /// \brief Test whether parsing produced a valid value.
    ///
    /// \return true if the parsed value is valid
    ///
    bool is_not_null() const {
        return value.is_not_null();
    }

    /// \brief Return the parsed value.
    ///
    /// \pre parsing succeeded
    /// \return the parsed value
    ///
    const Parser &get_value() const {
        return value;
    }

    /// \brief Return the original input extent.
    ///
    /// \return the original input
    ///
    datum get_raw() const {
        return raw;
    }

    /// \brief Return the bytes consumed by the parser.
    ///
    /// \pre parsing succeeded
    /// \return the parsed portion of the input
    ///
    datum get_parsed_data() const {
        if (!is_not_null()) {
            return datum{};
        }
        return datum{raw.data, trailer.data};
    }

    /// \brief Return bytes remaining after the parsed value.
    ///
    /// This is an empty datum when parsing consumed the complete input and a
    /// null datum when parsing failed.
    ///
    /// \return the unparsed trailer
    ///
    datum get_trailer() const {
        return trailer;
    }

    /// \brief Compare two parsed values and their trailers.
    ///
    /// Raw ordering agrees with the emitted bytes only when Parser preserves
    /// the bytes that decide its own validity and compares them first.
    ///
    /// \param other parsed value to compare
    /// \pre the inputs have equal length when either parse fails
    /// \return a negative, zero, or positive comparison result
    ///
    int compare(const parsed_extent &other) const {
        if (!is_not_null() || !other.is_not_null()) {
            assert(raw.length() == other.raw.length());
            return raw.cmp(other.raw);
        }

        int result = value.compare_degreased(other.value);
        if (result != 0) {
            return result;
        }
        return trailer.cmp(other.trailer);
    }

    /// \brief Write a parsed value followed by its original trailer.
    ///
    /// write_value must emit only the parsed portion. If parsing failed, the
    /// original input is emitted unchanged. Output must provide raw_as_hex().
    ///
    /// \param output output stream
    /// \param write_value parsed-value output function
    ///
    template <typename Output, typename WriteValue>
    void write(Output &output, WriteValue write_value) const {
        if (!is_not_null()) {
            if (raw.is_not_empty()) {
                output.raw_as_hex(raw.data, raw.length());
            }
            return;
        }

        write_value(output, value, get_parsed_data());
        if (trailer.is_not_empty()) {
            output.raw_as_hex(trailer.data, trailer.length());
        }
    }
};

#endif // PARSED_EXTENT_HPP
