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

class digit : public ignore_char_class<digit> {
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

#endif // LEX_H
