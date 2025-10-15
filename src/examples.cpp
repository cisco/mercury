// examples.cpp
//
// example usage of datum and related classes.
//
// compilation: g++ -Wall -Ilibmerc/ examples.cpp -o examples

#include <datum.h>
#include <lex.h>
#include <ctype.h>

int main(int argc, char *argv[]) {

    /// A datum represents a sequence of bytes in memory.  Below we
    /// create a short data buffer and initialize a datum that refers
    /// to it:
    ///
    ///                +------+------+
    ///     buffer     | 0x12 | 0x34 |
    ///                +------+------+
    ///                ^             ^
    ///                |             |
    ///     datum     data        data_end
    ///
    uint8_t buf[] = { 0x12, 0x34 };
    datum d{buf, buf + sizeof(buf)};

    /// It is easy to print a datum as hex to standard output, or any
    /// other FILE, using the member function \ref
    /// datum::fprint_hex().  Here we also print a newline for
    /// readability.
    ///
    d.fprint_hex(stdout); fputc('\n', stdout);  // output: "1234"

    /// A datum can be printed as an ASCII string using the function
    /// \ref datum::fprint().  Non-printable characters are
    /// represented with a `.`, as is conventional.
    ///
    d.fprint(stdout); fputc('\n', stdout);      // output: ".4"

    /// The number of bytes in a datum is returned by \ref
    /// datum::length().
    ///
    printf("d.length(): %zd\n", d.length());    // output: 2

    /// Every datum is in one of three states: null, readable, or
    /// empty.  If `datum::length()` is greater than zero, it is
    /// readable.  The functions \ref datum::is_null(), \ref
    /// datum::is_readable(), and \ref datum::is_not_empty() return
    /// booleans to indicate status:
    ///
    printf("d.is_null(): %u\n", d.is_null());           // output: 0 (false)
    printf("d.is_readable(): %u\n", d.is_readable());   // output: 1 (true)
    printf("d.is_emtpy(): %u\n", !d.is_not_empty());    // output: 0 (false)

    /// Creating a copy of a `datum` simply makes a copy of the `data`
    /// and `data_end` pointers, and does not make a copy of the data
    /// itself.  Creating a `datum` copy is simple:
    ///
    datum copy{d};

    /// An encoded unsigned integer can be constructed by passing a
    /// datum to the \ref encoded<> constructor, which takes as input
    /// a reference to a datum.
    ///
    encoded<uint16_t> e{d};
    printf("1234: %04x\n", e.value());    // output: 1234

    /// After we have read `e` from `d`, that `datum` is now empty,
    /// because the data pointer was advanced two bytes, and now
    /// coincides with the data_end pointer.
    ///
    ///                +------+------+
    ///     buffer     | 0x12 | 0x34 |
    ///                +------+------+
    ///                              ^
    ///                              |
    ///     datum               data=data_end
    ///
    /// An empty datum is not null, but has a zero length.
    ///
    printf("d.length(): %zd\n", d.length());            // output: 0
    printf("d.is_readable(): %u\n", d.is_readable());   // output: 0 (false)
    printf("d.is_null(): %u\n", d.is_null());           // output: 0 (false)

    /// If we try to read from an empty datum, it will be set to null.
    /// Here we construct an unnamed \ref encoded<uint16_t> object by
    /// reading from the empty datum `d`.
    ///
    encoded<uint16_t>{d};
    printf("d.length(): %zd\n", d.length());
    printf("d.is_readable(): %u\n", d.is_readable());
    printf("d.is_null(): %u\n", d.is_null());

    /// If `d::is_null()` returns true immediately after reading an
    /// object from `d`, then that read failed, and no more data can
    /// be read from it.  By convention, if there are not enough bytes
    /// in a datum that is passed to a constructor, then the datum is
    /// set to null.

    /// We use the following conventions for classes that can read
    /// from a \ref datum:
    ///
    ///   * it must not assume that the datum is readable, and it must
    ///     detect and ignore a null datum, without causing a fault,
    ///
    ///   * it must not access any bytes that are outside of the range
    ///     `{ data, data_end}`,
    ///
    ///   * if it is not possible to construct an object from the byte
    ///     sequence in the datum (for instance, if there are not
    ///     enough bytes), then the datum is set to the null state,
    ///
    ///   * it must advance the `data` pointer to reflect the extent
    ///     of the bytes consumed by decoding/parsing an object during
    ///     construction.
    ///
    /// These conventions facilitate composability: objects made by
    /// composing together objects that follow these conventions will
    /// also follow these conventions.
    ///

    /// More complex data types that can be decoded/parsed from a \ref
    /// datum can be created by taking advantage of a member
    /// initializer list.  When each of the members of the complex
    /// data type can read from a datum, the constructor of the
    /// complex data type simply consists of the successive
    /// invocations of the constructors of the member functions on the
    /// datum passed to the constructor of the complex data type.  In
    /// essence, the datum is passed to each of the members in turn.
    ///
    class udp {
        encoded<uint16_t> a;
        encoded<uint16_t> b;
        encoded<uint16_t> c;
        encoded<uint16_t> d;

    public:

        udp(datum &d) : a{d}, b{d}, c{d}, d{d} { }

        void print() {
            printf("{ %u, %u, %u, %u }\n", a.value(), b.value(), c.value(), d.value());
        }
    };

    /// It is easy to read a sequence of objects of the same class
    /// from a datum, using the \ref sequence<> class.  To illustrate
    /// this, we create a data buffer containing the byte string
    /// 0001020304050607, and parse it in several ways: as a sequence
    /// of `uint8_t`s, a sequence of `uint16_t`s, a sequence of
    /// `uint32_t`s, and as a sequence of `uint64_t`s.
    ///
    uint8_t buf2[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    datum d2{buf2, buf2 + sizeof(buf2)};
    udp pkt{d2};
    pkt.print();

    datum d3{buf2, buf2 + sizeof(buf2)};
    for (const auto & x : sequence<encoded<uint8_t>>{d3}) {
        printf("read uint8_t %02x\n", x.value());
    }
    // output: "read uint8_t 00"
    // output: "read uint8_t 01"
    // output: "read uint8_t 02"
    // output: "read uint8_t 03"
    // output: "read uint8_t 04"
    // output: "read uint8_t 05"
    // output: "read uint8_t 06"
    // output: "read uint8_t 07"

    for (const auto & x : sequence<encoded<uint16_t>>{d3}) {
        printf("read uint16_t %04x\n", x.value());
    }
    for (const auto & x : sequence<encoded<uint32_t>>{d3}) {
        printf("read uint32_t %08x\n", x.value());
    }
    for (const auto & x : sequence<encoded<uint64_t>>{d3}) {
        printf("read uint64_t %016zx\n", x.value());
    }

    datum truncated{buf2, buf2 + sizeof(buf2)-1 };
    for (const auto & x : sequence<encoded<uint32_t>>{truncated}) {
        printf("read uint32_t %08x\n", x.value());
        printf("is_readable(): %u\n", truncated.is_readable());
        printf("is_null(): %u\n", truncated.is_null());
    }

    class word : public one_or_more<word> {
    public:
        inline static bool in_class(const uint8_t &c) { return isalnum((char)c); }
    };
    class whitespace : public one_or_more<whitespace> {
    public:
        inline static bool in_class(const uint8_t &c) { return isspace((char)c); }
    };

    uint8_t sentence[] = "The quick brown fox jumped over the lazy dog.";
    datum s{sentence, sentence + sizeof(sentence)};
    while (s.is_readable()) {
        word w{s};
        w.fprint(stdout);
        printf("\n");
        whitespace{s};
    }

    class token {
        word w;
        optional<whitespace> space;

    public:

        token(datum &d) : w{d}, space{d} { }

        void print() const { w.fprint(stdout); }
    };

    s = {sentence, sentence + sizeof(sentence)};
    for (const auto & t : sequence<token>{s}) {
        t.print();
        printf(".");
    }
    printf("\n");

    // reading bitfields
    //
    uint8_t fields[] = { 0b11110000 };
    s = { fields, fields + sizeof(fields) };
    encoded<uint8_t> f{s};

    printf("bit 0: %x\n", f.bit<0>());
    printf("bit 1: %x\n", f.bit<1>());
    printf("bit 2: %x\n", f.bit<2>());
    printf("bit 3: %x\n", f.bit<3>());
    printf("bit 4: %x\n", f.bit<4>());
    printf("bit 5: %x\n", f.bit<5>());
    printf("bit 6: %x\n", f.bit<6>());
    printf("bit 7: %x\n", f.bit<7>());

    // slices
    //
    printf("slice<0,4>: %x\n", f.slice<0,4>());
    printf("slice<5,8>: %x\n", f.slice<5,8>());
    printf("slice<2,6>: %x\n", f.slice<3,6>());

    /// To create a class that accepts a variable-length sequence of
    /// alphabetic characters, or a sequence of decimial digits, we can
    /// use the template class one_or_more<>.  We define a new class
    /// `alphabetic` that meets our needs by deriving it from
    /// `one_or_more<alphabetic>`, and then defining the static member
    /// function `bool in_class(x)` that returns true only when `x` is
    /// in that class.  Having the class name appear as a template
    /// parameter of a parent class achieves compile-time polymorphism,
    /// and is called the Curiously Recurring Template Pattern (CRTP).
    ///
    class alphabetic : public one_or_more<alphabetic> {
    public:
        inline static bool in_class(uint8_t x) {
            return isalpha((char)x);
        }
    };
    class numeric : public one_or_more<numeric> {
    public:
        inline static bool in_class(uint8_t x) {
            return isdigit((char)x);
        }
    };

    uint8_t vowels_and_punct[] = {'a', 'e', 'i', 'o', 'u', 'y', '.', '!', '?'};
    datum vp{vowels_and_punct, vowels_and_punct + sizeof(vowels_and_punct)};
    uint8_t primes[] = {'3', '5', '7'};
    datum p{primes, primes + sizeof(primes)};

    alphabetic alpha{vp};
    if (!vp.is_null()) {
        alpha.fprint(stdout); fputc('\n', stdout);
        vp.fprint(stdout); fputc('\n', stdout);
    }

    // When we are not sure if a datum contains data that can be read
    // by a class C, we can create a temporary copy of the datum and
    // then attempt to construct an object of type C from that object.
    // If the read was successful, then we can use that object, and if
    // needed, we can advance the original datum forward to reflect
    // the bytes accepted during the construction of that object.
    //
    // The template class \ref lookahead<> performs all of these steps
    // for you.
    //
    if (lookahead<alphabetic> alpha{p}) {
        printf("read one or more alphabetic characters\n");
    } else if (lookahead<numeric> num{p}) {
        printf("read one or more numeric characters\n");
        num.value.fprint(stdout); fputc('\n', stdout);
        p = num.advance();
    }

    // TODO: add examples for the following classes
    //

    // ignore
    //

    // optional
    //

    // packets
    //

    // address strings
    //

    // addresses
    //

    return 0;
}
