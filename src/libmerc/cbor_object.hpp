// cbor_object.hpp

#ifndef CBOR_OBJECT_HPP
#define CBOR_OBJECT_HPP

#include "datum.h"
#include "cbor.hpp"

class cbor_array;

class cbor_object {
    cbor::output::map m;

    static writeable &create_named_map(const char *key, cbor_object &o) {
        cbor::text_string{key}.write(o.m);
        return o.m;
    }

    friend class cbor_array;

public:

    cbor_object(writeable &w) : m{w} { }

    cbor_object(cbor_object &o, const char *key) : m{create_named_map(key, o)} { }

    cbor_object(cbor_array &a);

    void print_key_uint(const char *key, uint64_t value) {
        cbor::text_string{key}.write(m);
        cbor::uint64{value}.write(m);
    }

    void print_key_string(const char *key, const char *str) {
        cbor::text_string{key}.write(m);
        cbor::text_string{str}.write(m);
    }

    void print_key_hex(const char *key, datum bytes) {
        cbor::text_string{key}.write(m);
        cbor::byte_string::construct(bytes).write(m);
    }

    void print_key_bool(const char *key, bool b) {
        cbor::text_string{key}.write(m);
        cbor::initial_byte{cbor::simple_or_float_type, b ? cbor::initial_byte::True : cbor::initial_byte::False}.write(m);
    }

    void print_key_null(const char *key) {
        cbor::text_string{key}.write(m);
        cbor::initial_byte{cbor::simple_or_float_type, cbor::initial_byte::null}.write(m);
    }

    void close() { m.close(); }

};

class cbor_array {
    cbor::output::array a;

    static writeable &create_named_array(const char *key, cbor_object &o) {
        cbor::text_string{key}.write(o.m);
        return o.m;
    }

    friend class cbor_object;

public:

    cbor_array(writeable &w) : a{w} { }

    cbor_array(cbor_object &o, const char *key) : a{create_named_array(key, o)} { }

    void close() { a.close(); }

};

cbor_object::cbor_object(cbor_array &outer) : m{outer.a} { }


#endif // CBOR_OBJECT_HPP
