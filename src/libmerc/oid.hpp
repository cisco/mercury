// oid.hpp
//

#ifndef OID_HPP
#define OID_HPP

#include <array>

namespace asn1 {

    /// returns a `std::array` containing the byte sequence of the the
    /// ASN.1 Object Identifier (OID) with the numerical sequence U0, U1,
    /// ....
    ///
    /// \example
    /// ```cpp
    ///     constexpr auto oid_rsadsi = oid<1,2,840,113549>();
    /// ```
    ///
    template <unsigned U0, unsigned U1, unsigned... Us>
    constexpr auto oid();


    /// returns a `std::array` containing the byte sequence of the the
    /// ASN.1 OID sub-identifier with the numerical sequence Us, ...
    /// ....
    ///
    /// This function returns a byte array corresponding to a
    /// sub-identifier.  It can be appended to another byte string
    /// that represents and OID using the `+` operator, to create a
    /// sub-OID.
    ///
    /// Note: this function can only be used to extend OIDs created
    /// with the \ref asn1::oid() function.  It cannot create an OID
    /// by itself, because the first two bytes of an OID have a
    /// special encoding.
    ///
    /// \example
    /// ```cpp
    ///     constexpr static auto id_pkix = oid<1,3,6,1,5,5,7>();
    ///     constexpr static auto id_ad = id_pkix + suboid<48>();
    /// ```
    ///
    template <unsigned... Us>
    constexpr auto suboid();


    /// returns the `std::array<uint8_t, M+N>` formed as the contacenation
    /// of \param x and \param y
    ///
    /// \note: this function is a helper used in oid<>().
    ///
    template<size_t M, size_t N>
    constexpr std::array<uint8_t, M + N> operator+(const std::array<uint8_t, M> &x,
                                                   const std::array<uint8_t, N> &y) {
        std::array<uint8_t, M + N> z{};
        size_t i=0;
        for ( ; i<M; i++) {
            z[i] = x[i];
        }
        for (size_t j=0; j<N; j++) {
            z[j+i] = y[j];
        }
        return z;
    }

    /// returns the number of digits in the base-128 representation of
    /// \param U, with the convention that zero is represented with a
    /// single digit.
    ///
    /// \note: This function returns the number of bytes needed to encode
    /// an ASN.1 OID subidentifier.
    ///
    constexpr size_t num_base_128_digits(size_t U) {
        if (U == 0) {
            return 1;
        }
        size_t digits = 0;
        while (U > 0) {
            U = U / 128;
            digits++;
        }
        return digits;
    }

    /// returns a `std::array` containing the byte sequence corresponding
    /// to the OID node `U`
    ///
    template <unsigned U>
    constexpr std::array<uint8_t, num_base_128_digits(U)> node_array() {
        std::array<uint8_t, num_base_128_digits(U)> result{};
        unsigned tmp = U;
        if (tmp == 0) {
            result[0] = 0;
        } else {
            ssize_t i=num_base_128_digits(U)-1;
            while (tmp > 0) {
                while (tmp > 0) {
                    unsigned div = tmp/128;
                    unsigned rem = tmp - div * 128;
                    result[i--] = rem;
                    tmp = div;
                }
            }
            assert(i == -1);
        }

        for (size_t i=0; i<num_base_128_digits(U)-1; i++) {
            result[i] |= 0x80;
        }

        return result;
    }


    template <unsigned N0, unsigned N1, unsigned... Ns>
    constexpr auto oid() {
        static_assert(N0 < 3, "top level OID component must be less than 3");
        static_assert(N0*40+N1 < 128, "top level OID components too large");
        return (std::array<uint8_t, 1>{N0*40+N1} + ... + node_array<Ns>());
    }

    template <unsigned... Ns>
    constexpr auto suboid() {
        return ( ... + node_array<Ns>());
    }

    // Implementation Notes
    //
    // ASN.1 OIDs are defined by these standards:
    //
    //  ITU-T X.680 : Information technology – Abstract Syntax Notation
    //  One (ASN.1): Specification of basic notation/
    //
    //  ITU-T X.690 : Information technology – ASN.1 encoding rules:
    //  Specification of Basic Encoding Rules (BER), Canonical Encoding
    //  Rules (CER) and Distinguished Encoding Rules (DER)
    //
    //  ITU-T X.660 : Information technology – Procedures for the
    //  operation of object identifier registration authorities: General
    //  procedures and top arcs of the international object identifier
    //  tree
    //
    //
    // Following X.680 Section 8.19, "Encoding of an object identifier
    // value":
    //
    //    The contents (value) of an OID is an ordered list of encodings
    //    of subidentifiers. Each subidentifier is represented as a series
    //    of (one or more) octets.  The most significant bit of each octet
    //    indicates whether it is the last in the series: it is zero for
    //    the last octet, while it is one for each preceding octet. The
    //    remaining seven bits of the octets in the series collectively
    //    encode the subidentifier.  The number of subidentifiers is one
    //    less than the number of OID components.
    //
    //    The numerical value of the first subidentifier Z is derived from
    //    the values of the first two OID components as Z=(X*40)+Y, where
    //    X and Y are the values of the first and second OID components,
    //    respectively, and X < 3.
    //
    // Object Identifier (OID) values are required to have at least two
    // components.
    //
    // Let U = r_{m} 128^m + r_{m-1} 128^{m-1} + ... + r_{1} 128 + r_{0}
    // be the base-128 representation of U.  Then the contents of the OID
    // consists of
    //
    //   r_{m} | 0x80, r_{m-1} | 0x80, ..., r_{1} | 0x80, r_{0}
    //




    //
    // Unit test for OID
    //

    // return true if \param lhs equals \param rhs, otherwise return
    // false; if \param f is non-NULL, print out verbose debugging
    // information to that `FILE`.
    //
    template <size_t N>
    static bool compare(const std::array<uint8_t, N> &lhs,
                        const std::array<uint8_t, N> &rhs,
                        FILE *f=nullptr) {
        if (lhs != rhs) {
            if (f) {
                fprintf(f, "error: test case mismatch\n");
                fprintf(f, "computed: { ");
                for (const auto &x : lhs) {
                    fprintf(f, "0x%02x, ", x);
                }
                fprintf(f, " }\n");
                fprintf(f, "expected: { ");
                for (const auto &x : rhs) {
                    fprintf(f, "0x%02x, ", x);
                }
                fprintf(f, " }\n");
            }
            return false;
        }
        return true;
    }


    // returns true if OID unit tests passed, and false otherwise; if
    // \param f is non-NULL, print out verbose debugging information to
    // that `FILE`.
    //
    // \note: the unit tests may fail either at run time or at compile time
    //
    static bool oid_unit_test(FILE *f=nullptr) {
        constexpr auto oid_id_pkix_ocsp_basic = oid<1,3,6,1,5,5,7,48,1,1>();
        constexpr auto oid_rsadsi = oid<1,2,840,113549>();
        constexpr static auto id_pkix = oid<1,3,6,1,5,5,7>();
        constexpr static auto id_ad = id_pkix + suboid<48>();

        bool all_passed = true;
        all_passed &= compare(oid_id_pkix_ocsp_basic, std::array<uint8_t, 9>{ 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01 });
        all_passed &= compare(oid_rsadsi, std::array<uint8_t, 6>{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d });
        all_passed &= compare(oid_id_pkix_ocsp_basic, id_ad + suboid<1,1>());

        return all_passed;
    }

}  // namespace asn1


#endif // OID_HPP
