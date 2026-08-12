// null_terminated_string.hpp
//
// Copyright (c) 2026 Cisco Systems, Inc. All rights reserved.
// License at https://github.com/cisco/mercury/blob/master/LICENSE

#ifndef NULL_TERMINATED_STRING_HPP
#define NULL_TERMINATED_STRING_HPP

#include <cassert>
#include <cstddef>
#include <stdexcept>

/// \brief Non-owning wrapper for a non-null, null-terminated string.
///
/// This type marks APIs that require a valid C string.  It stores only
/// the pointer supplied by the caller; the caller is responsible for
/// keeping the pointed-to string alive for the wrapper's lifetime.
///
/// String literals use the constexpr array constructor.  Runtime
/// strings should use \ref checked when the length is already known and
/// should use \ref assume only when the caller has established the
/// invariant by other means.
///
class null_terminated_string {
    const char *s;

    struct unchecked {};

    constexpr null_terminated_string(const char *p, unchecked) noexcept : s{p} { }

public:

    /// \brief Constructs from a string literal or const character array.
    ///
    /// The array must include its terminating null byte.  In constant
    /// evaluation this constructor can be used to create constexpr keys;
    /// in debug builds it also asserts that the last array element is
    /// `'\0'`.
    ///
    /// \tparam N number of bytes in \p literal, including the terminator.
    /// \param literal character array whose final element is `'\0'`.
    ///
    template <std::size_t N>
    constexpr null_terminated_string(const char (&literal)[N]) noexcept : s{literal} {
        static_assert(N > 0, "null_terminated_string requires a char array");
        assert(literal[N - 1] == '\0');
    }

    /// \brief Rejects mutable character arrays.
    ///
    /// Mutable arrays are commonly runtime buffers.  Use \ref checked
    /// with the known string length after populating such a buffer.
    ///
    template <std::size_t N>
    null_terminated_string(char (&)[N]) = delete;

    /// \brief Rejects construction from `nullptr`.
    ///
    null_terminated_string(std::nullptr_t) = delete;

    /// \brief Constructs from a runtime string and validates the invariant.
    ///
    /// This factory checks the pointer and the byte at \p len; it does
    /// not call `strlen()` or scan the string.
    ///
    /// \param p pointer to the first byte of the string.
    /// \param len number of bytes before the expected terminating null.
    /// \return a wrapper around \p p.
    /// \throws std::invalid_argument if \p p is null or `p[len] != '\0'`.
    ///
    static null_terminated_string checked(const char *p, std::size_t len) {
        if (p == nullptr || p[len] != '\0') {
            throw std::invalid_argument{"invalid null_terminated_string"};
        }
        return null_terminated_string{p, unchecked{}};
    }

    /// \brief Constructs from a runtime string whose invariant is assumed.
    ///
    /// This factory performs no release-build validation.  It is for
    /// call sites where the pointer is known to be non-null and
    /// null-terminated by construction.
    ///
    /// \param p pointer to a non-null, null-terminated string.
    /// \return a wrapper around \p p.
    ///
    static null_terminated_string assume(const char *p) noexcept {
        assert(p != nullptr);
        return null_terminated_string{p, unchecked{}};
    }

    /// \brief Returns the wrapped C string pointer.
    ///
    /// \return the non-null, null-terminated string pointer.
    ///
    constexpr const char *c_str() const noexcept { return s; }
};

#endif // NULL_TERMINATED_STRING_HPP
