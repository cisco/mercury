// cbor_object.hpp

#ifndef CBOR_OBJECT_HPP
#define CBOR_OBJECT_HPP

#include "datum.h"
#include "cbor.hpp"

class cbor_array;
template <size_t N> class cbor_object_compact;

class cbor_object {
    cbor::output::map m;

    static writeable &create_named_map(const char *key, cbor_object &o) {
        cbor::text_string{key}.write(o.m);
        return o.m;
    }

    static writeable &create_named_map(uint64_t k, cbor_object &o) {
        cbor::uint64{k}.write(o.m);
        return o.m;
    }

    friend class cbor_array;

    template <size_t N> friend class cbor_object_compact;

public:

    cbor_object(writeable &w) : m{w} { }

    cbor_object(cbor_object &o, const char *key) : m{create_named_map(key, o)} { }

    template <size_t N>
    cbor_object(cbor_object_compact<N> &o, const char *key);

    cbor_object(cbor_array &a);

    ~cbor_object() { close(); }

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

    ~cbor_array() { close(); }

    void close() { a.close(); }

    void print_string(const char *str) {
        cbor::text_string{str}.write(a);
    }

};

cbor_object::cbor_object(cbor_array &outer) : m{outer.a} { }



#include "static_dict.hpp"

template <size_t N>
class cbor_object_compact : public cbor_object {
    const static_dictionary<N> &dict;

    friend class cbor_object;

public:

    cbor_object_compact(writeable &w, const static_dictionary<N> &d) : cbor_object{w}, dict{d} {}

    template <size_t M>
    cbor_object_compact(cbor_object_compact<M> &o, const char *key, const static_dictionary<N> &d) : cbor_object{o,key}, dict{d} {}

    ~cbor_object_compact() { close(); }

    void print_key_uint(const char *key, uint64_t value) {
        cbor::uint64{dict.index(key)}.write(m);
        cbor::uint64{value}.write(m);
    }

    void print_key_string(const char *key, const char *str) {
        cbor::uint64{dict.index(key)}.write(m);
        cbor::text_string{str}.write(m);
    }

    void print_key_hex(const char *key, datum bytes) {
        cbor::uint64{dict.index(key)}.write(m);
        cbor::byte_string::construct(bytes).write(m);
    }

    void print_key_float(const char *key, datum bytes) {
        cbor::uint64{dict.index(key)}.write(m);
        cbor::byte_string::construct(bytes).write(m);
    }

    void print_key_bool(const char *key, bool b) {
        cbor::uint64{dict.index(key)}.write(m);
        cbor::initial_byte{cbor::simple_or_float_type, b ? cbor::initial_byte::True : cbor::initial_byte::False}.write(m);
    }

    void print_key_null(const char *key) {
        cbor::uint64{dict.index(key)}.write(m);
        cbor::initial_byte{cbor::simple_or_float_type, cbor::initial_byte::null}.write(m);
    }

};

template <size_t N>
cbor_object::cbor_object(cbor_object_compact<N> &o, const char *key) : m{create_named_map(o.dict.index(key), o)} { }



/// implements an ordered array of strings that can be used to map
/// strings to and from short integers
///
class vocabulary {
    std::vector<std::string> a;

public:

    // decode a CBOR vocabulary object
    //
    vocabulary(datum &d) {
        cbor::map outer{d};
        cbor::text_string key = cbor::text_string::decode(d);  // TODO: check "words"
        if (key.value().equals(std::array<uint8_t,5>{'w', 'o', 'r', 'd', 's'})) {
            cbor::array words{d};
            while (d.is_not_empty()) {
                if (lookahead<cbor::initial_byte> ib{d}) {
                    switch (ib.value.major_type()) {
                    case cbor::text_string_type:
                        {
                            cbor::text_string word = cbor::text_string::decode(d);
                            if (d.is_null()) {
                                break;
                            }
                            a.push_back(word.value().get_string());
                        }
                        break;
                    default:
                        goto exit_loop;
                    }
                } else {
                    break;
                }
            }
        exit_loop: ;
        } else {
        ; // ignore unknown key
        }
    }

    void dump() {
        for (const auto & w : a) {
            fprintf(stdout, "vocabulary: %s\n", w.c_str());
        }
    }

};

#endif // CBOR_OBJECT_HPP
