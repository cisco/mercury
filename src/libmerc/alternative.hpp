/// \file alternative.hpp
/// \brief Defines ordered PEG alternatives and overload helpers for parser visitors.
///
/// Copyright (c) 2026 Cisco Systems, Inc. All rights reserved.  License at
/// https://github.com/cisco/mercury/blob/master/LICENSE

#ifndef ALTERNATIVE_HPP
#define ALTERNATIVE_HPP

#include <variant>
#include <utility>

#include "datum.h"


/// \brief Represents a non-object resulting from a parse failure.
class nulltype {
public:
    /// \brief Construct a null object from a failed parse attempt.
    /// \param[in] d Datum corresponding to the failed parse attempt.
    nulltype(datum &) { }

    /// \brief Construct a null object without parser input.
    nulltype() { }
};


/// \brief Combines multiple function objects into a single overload set.
/// \tparam Ts Function object types that provide `operator()`.
template<typename... Ts> struct overloaded : Ts... { using Ts::operator()...; };

/// \brief Shorter overload helper that supports class template argument deduction.
/// \tparam Ts Function object types that provide `operator()`.
template<typename... Ts> struct lambda : Ts... { using Ts::operator()...; };

/// \brief Deduction guide for \ref overloaded.
/// \tparam Ts Function object types that provide `operator()`.
template<typename... Ts> overloaded(Ts...) -> overloaded<Ts...>;

/// \brief Deduction guide for \ref lambda.
/// \tparam Ts Function object types that provide `operator()`.
template<typename... Ts> lambda(Ts...) -> lambda<Ts...>;
/// \brief Implements an ordered Parsing Expression Grammar (PEG) alternative.
///
/// `alternative<T1, T2, ...>` attempts to parse the input as `T1`, then `T2`,
/// and so on, halting after the first success. This is similar to a
/// Backus-Naur Form alternative, but ordered.
///
///     `a = T1 / T2 / ...`
///
/// \tparam Types Parser types that are tried in order.
///         Each type must be constructible from `datum &`.
template<typename... Types>
class alternative {

public:

    static_assert((is_datum_initializable<Types>::value && ...),
                  "alternative<Types...> requires each type to be initializable from datum&");

    /// \brief Variant type holding the first successful parse result or \ref nulltype.
    using type = std::variant<Types..., nulltype>;

    /// \brief Construct an ordered alternative from parser input.
    /// \param[in,out] d Input datum that is advanced only for the first successful parse.
    alternative(datum &d) : member{construct(d)} { }

    /// \brief Parse the first matching alternative from a datum.
    /// \tparam I Index of the alternative currently being tested.
    /// \param[in,out] d Input datum that is advanced only for the first successful parse.
    /// \return An \ref alternative::type containing the first successful parse result,
    ///         or \ref nulltype if no alternative matches.
    template <size_t I = 0>
    static type construct(datum &d) {
        if constexpr (I < sizeof...(Types)) {
            datum tmp{d};
            using candidate_type = std::variant_alternative_t<I, std::variant<Types...>>;
            candidate_type object{tmp};
            if (tmp.is_not_null()) {
                d = tmp;
                return object;
            }
            return construct<I + 1>(d);
        }
        return nulltype{};
    }

    /// \brief Apply a visitor to the stored alternative.
    /// \tparam Functor Visitor type accepted by `std::visit()`.
    /// \param[in] operation Visitor applied to the stored variant value.
    /// \return Whatever `std::visit()` returns for `operation` and the stored alternative.
    template <typename Functor>
    decltype(auto) apply(Functor &&operation) {
        return std::visit(std::forward<Functor>(operation), member);
    }

    /// \brief Apply a visitor to the stored alternative in a const object.
    /// \tparam Functor Visitor type accepted by `std::visit()`.
    /// \param[in] operation Visitor applied to the stored variant value.
    /// \return Whatever `std::visit()` returns for `operation` and the stored alternative.
    template <typename Functor>
    decltype(auto) apply(Functor &&operation) const {
        return std::visit(std::forward<Functor>(operation), member);
    }

private:

    std::variant<Types...,nulltype> member;

};

#endif // ALTERNATIVE_HPP
