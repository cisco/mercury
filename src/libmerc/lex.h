// lex.h

#ifndef LEX_H
#define LEX_H

#include "datum.h"

// class ignore_char_class accepts and ignores a single character,
// defined by the function static bool D::in_class(uint8_t), defined
// in the class D.  This implementation uses the Curiously Recurring
// Template Pattern (CRTP).
//
template <class D>
class ignore_char_class {
public:
    ignore_char_class(datum &d) {
        if (lookahead<encoded<uint8_t>> tmp{d}) {
            if (D::in_class(tmp.value)) {
                d = tmp.advance();
                return;
            }
        }
        d.set_null();
    }
};

template <class char_class>
class one {
public:
    one(datum &d) {
        if (lookahead<encoded<uint8_t>> tmp{d}) {
            if (char_class::in_class(tmp.value)) {
                d = tmp.advance();
            } else {
                d.set_null();
            }
        }
    }
};

class decimal_digit : public ignore_char_class<decimal_digit> {
public:
    inline static bool in_class(uint8_t x) {
        return x >= '0' && x <= '9';
    }
};

// class space implements HTTP 'linear white space' (LWS)
//
class space : public ignore_char_class<space> {
public:
    inline static bool in_class(uint8_t x) {
        return x == ' ' || x == '\t';
    }
};

// class exactly_n<char_class> parses a datum that holds one or more
// uint8_ts in the character class char_class.  It is implemented
// using the CRTP (Curiously Recurring Template Pattern).
//
template <class char_class>
class exactly_n : public datum {
public:
    exactly_n(datum &d, size_t n) {
        this->data = d.data;

        while (d.is_not_empty() and n > 0) {
            if (lookahead<encoded<uint8_t>> y{d}) {
                if (char_class::in_class(y.value)) {
                    d = y.advance();
                } else {
                    d.set_null();
                    set_null();
                    break;
                }
            } else {
                break;
            }
        }

        this->data_end = d.data;
    }
};

// class one_or_more<char_class> parses a datum that holds one or more
// uint8_ts in the character class char_class.  It is implemented
// using the CRTP (Curiously Recurring Template Pattern).
//
template <class char_class>
class one_or_more : public datum {
public:
    one_or_more(datum &d) {
        this->data = d.data;

        if (lookahead<encoded<uint8_t>> x{d}) {
            if (char_class::in_class(x.value)) {
                d = x.advance();
                while (d.is_not_empty()) {
                    if (lookahead<encoded<uint8_t>> y{d}) {
                        if (char_class::in_class(y.value)) {
                            d = y.advance();
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                this->data_end = d.data;
                return;
            } else {
                set_null();
            }
        }
        d.set_null();
        set_null();
    }
};

class digits : public one_or_more<decimal_digit> {
public:
    inline static bool in_class(uint8_t x) {
        return x >= '0' && x <= '9';
    }
};

class hex_digits : public one_or_more<hex_digits> {
public:
    inline static bool in_class(uint8_t x) {
        return (x >= '0' && x <= '9') || (x >= 'a' && x <= 'f') || (x >= 'A' && x <= 'F');
    }
};

class alpha_numeric : public one_or_more<alpha_numeric> {
public:
    inline static bool in_class(uint8_t x) {
        return std::isalnum(static_cast<unsigned char>(x));
    }
};

template <uint8_t byte>
class up_to_required_byte : public datum {
public:
    up_to_required_byte(datum &d) {
        if (d.data == nullptr || d.data == d.data_end) {
            d.set_null();
            return;
        }
        const uint8_t *location = (const uint8_t *)memchr(d.data, byte, d.length());
        if (location == nullptr) {
            this->set_null();
            d.set_null();
        }
        data_end = location;
        data = d.data;
        d.data = location;
    }
};

class crlf {
    literal_byte<'\r', '\n'> value;

public:
    crlf(struct datum &p) : value(p) { }
};

class uppercase : public one_or_more<uppercase> {
public:
    inline static bool in_class(uint8_t x) {
        return x >= 'A' && x <= 'Z';
    }
};
#endif // LEX_H
