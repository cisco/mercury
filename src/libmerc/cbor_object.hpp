// cbor_object.hpp

#ifndef CBOR_OBJECT_HPP
#define CBOR_OBJECT_HPP

#include "datum.h"
#include "cbor.hpp"
#include "static_dict.hpp"
#include <stdexcept>

// forward declarations
//
class cbor_array;
template <size_t N> class cbor_object_compact;

/// represents a CBOR map
///
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

    cbor_array(cbor_object &o, const char *key) : a{create_named_array(key, o)} { }


    /// create a nested CBOR array
    ///
    /// implementation note: the cast to \ref writeable is needed to
    /// prevent the \ref cbor::output::array copy constructor from
    /// being used instead of a conversion to \ref writeable
    ///
    cbor_array(cbor_array &outer_array) : a{(writeable &)outer_array.a} { }

    void print_string(const char *str) {
        cbor::text_string{str}.write(a);
    }

    void close() { a.close(); }

};

cbor_object::cbor_object(cbor_array &outer) : m{outer.a} { }


template <size_t N>
class cbor_object_compact : public cbor_object {
    const static_dictionary<N> &dict;

    friend class cbor_object;

public:

    cbor_object_compact(writeable &w, const static_dictionary<N> &d) : cbor_object{w}, dict{d} {}

    template <size_t M>
    cbor_object_compact(cbor_object_compact<M> &o, const char *key, const static_dictionary<N> &d) : cbor_object{o,key}, dict{d} {}

    // ~cbor_object_compact() { close(); }

    void print_key_uint(const char *key, uint64_t value) {
        cbor::uint64{dict.index(key)}.write(m);
        cbor::uint64{value}.write(m);
    }

    void print_key_string(const char *key, const char *str) {
        cbor::uint64{dict.index(key)}.write(m);
        cbor::text_string{str}.write(m);
    }

    void print_key_string(size_t idx, const char *str) {
        cbor::uint64{idx}.write(m);
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

    template <size_t N>
    vocabulary(const static_dictionary<N> &dict) {
        for (const auto & word : dict) {
            a.push_back(word);
        }
    }

    // decode a CBOR vocabulary object
    //
    vocabulary(datum &d) {
        cbor::map outer{d};
        cbor::text_string key = cbor::text_string::decode(d);
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

    const char *word(size_t idx) const {
        if (idx < a.size()) {
            return a[idx].c_str();
        }
        return "UKNOWN";  // note: could report unknown integer value as string
    }

};

#include "json_object.h"
#include "utf8.hpp"

class cbor_to_json_translator {
    const vocabulary *keys;

    enum type { key, value };

public:

    cbor_to_json_translator() : keys{nullptr} { }

    cbor_to_json_translator(const vocabulary *v) : keys{v} { }

    inline bool decode_cbor_array_to_json(datum &d, json_array &a);

    inline bool decode_cbor_map_to_json(datum &d, json_object &o) {

        type expected_type = key;
        const char *key = nullptr;

        output_buffer<128> key_buf;

        while (d.is_readable()) {
            if (lookahead<cbor::initial_byte> ib{d}) {
                // fprintf(stderr, "initial_byte: %02x\tmajor_type: %u\tadditional_info: %u\n", ib.value.value(), ib.value.major_type(), ib.value.additional_info());

                if (expected_type == type::key) { // store key for use with next value
                    switch (ib.value.major_type()) {

                    case cbor::unsigned_integer_type:
                        {
                            cbor::uint64 tmp{d};
                            if (d.is_null()) { return false; }
                            if (keys == nullptr) {
                                key_buf.reset();
                                key_buf.write_uint16(tmp.value());
                                key_buf.add_null();
                                key = key_buf.data();
                            } else {
                                key = keys->word(tmp.value());
                            }
                        }
                        break;
                    case cbor::text_string_type:
                        {
                            cbor::text_string tmp = cbor::text_string::decode(d);
                            if (d.is_null()) { return false; }
                            key_buf.reset();
                            utf8_string::write(key_buf, tmp.value().data, tmp.value().length());
                            key_buf.add_null();
                            key = key_buf.data();
                        }
                        break;
                    case cbor::simple_or_float_type:
                        if (ib.value.value() == 0xff) {
                            d = ib.advance();
                            return true;      // end of map
                        }
                        [[fallthrough]];
                    default:
                        fprintf(stderr, "unexpected initial byte in cbor map key: 0x%02x\n", ib.value.value());
                        return false;
                    }

                    if (key == nullptr) {
                        fprintf(stderr, "error: null key\n");
                        return false;
                    }
                    expected_type = type::value;

                } else if (expected_type == type::value) {

                    switch (ib.value.major_type()) {
                    case cbor::unsigned_integer_type:
                        {
                            cbor::uint64 tmp{d};
                            if (d.is_null()) { return false; }
                            o.print_key_uint(key, tmp.value());
                        }
                        break;
                    case cbor::byte_string_type:
                        {
                            cbor::byte_string tmp = cbor::byte_string::decode(d);
                            if (d.is_null()) { return false; }
                            o.print_key_hex(key, tmp.value());
                        }
                        break;
                    case cbor::text_string_type:
                        {
                            cbor::text_string tmp = cbor::text_string::decode(d);
                            if (d.is_null()) { return false; }
                            o.print_key_json_string(key, tmp.value());
                        }
                        break;
                    case cbor::array_type:
                        {
                            cbor::array tmp{d};
                            if (d.is_null()) { return false; }
                            json_array a{o, key};
                            bool success = decode_cbor_array_to_json(d, a);
                            a.close();
                            if (!success) { return false; }
                        }
                        break;
                    case cbor::map_type:
                        {
                            cbor::map tmp{d};
                            if (d.is_null()) { return false; }
                            d = ib.advance();
                            json_object map{o, key};
                            bool success = decode_cbor_map_to_json(d, map);
                            map.close();
                            if (!success) { return false; }
                        }
                        break;
                    case cbor::tagged_item_type:
                        {
                            cbor::tag tmp{d};
                            if (d.is_null()) { return false; }
                        }
                        break;
                    case cbor::simple_or_float_type:
                        if (ib.value.value() == 0xff) {
                            fprintf(stderr, "cbor_object missing value\n");
                            return false;
                        } else if (ib.value.additional_info() == cbor::initial_byte::True) {
                            o.print_key_bool(key, true);
                            d = ib.advance();
                            break;
                        } else if (ib.value.additional_info() == cbor::initial_byte::False) {
                            o.print_key_bool(key, false);
                            d = ib.advance();
                            break;
                        } else if (ib.value.additional_info() == cbor::initial_byte::null) {
                            o.print_key_null(key);
                            d = ib.advance();
                            break;
                        }
                        [[fallthrough]];
                    default:
                        fprintf(stderr, "unexpected initial byte in cbor map value: 0x%02x\n", ib.value.value());
                        return false;
                    }

                    key = nullptr;
                    expected_type = type::key;
                }

            } else {
                return false;  // could not read initial byte
            }

        }

        fprintf(stderr, "GOT TO END of %s\n", __func__);
        return false;
    }

};

inline bool cbor_to_json_translator::decode_cbor_array_to_json(datum &d, json_array &a) {
    while (d.is_readable()) {
        if (lookahead<cbor::initial_byte> ib{d}) {
            //fprintf(f, "initial_byte: %02x\tmajor_type: %u\n", ib.value.value(), ib.value.major_type());
            switch (ib.value.major_type()) {
            case cbor::unsigned_integer_type:
                {
                    cbor::uint64 tmp{d};
                    if (d.is_null()) { return false; }
                    a.print_uint(tmp.value());
                }
                break;
            case cbor::byte_string_type:
                {
                    cbor::byte_string tmp = cbor::byte_string::decode(d);
                    if (d.is_null()) { return false; }
                    a.print_hex(tmp.value());
                }
                break;
            case cbor::text_string_type:
                {
                    cbor::text_string tmp = cbor::text_string::decode(d);
                    if (d.is_null()) { return false; }
                    a.print_json_string(tmp.value());
                }
                break;
            case cbor::array_type:
                {
                    cbor::array tmp{d};
                    if (d.is_null()) { return false; }
                    json_array inner_array{a};
                    bool success = decode_cbor_array_to_json(tmp, inner_array);
                    inner_array.close();
                    if (!success) { return false; }
                }
                break;
            case cbor::map_type:
                {
                    cbor::map tmp{d};
                    if (d.is_null()) { return false; }
                    d = ib.advance();
                    json_object map{a};
                    bool success = decode_cbor_map_to_json(d, map);
                    map.close();
                    if (!success) { return false; }
                }
                break;
            case cbor::tagged_item_type:
                {
                    cbor::tag tmp{d};
                    if (d.is_null()) { return false; }
                    // ??????????????????????
                }
                break;
            case cbor::simple_or_float_type:
                if (ib.value.value() == 0xff) {
                    d = ib.advance();
                    return true;
                }
                [[fallthrough]];
            default:
                fprintf(stderr, "unexpected initial byte in cbor array element: 0x%02x\n", ib.value.value());
                return false;
            }
        }
    }
    return true;
}


static inline bool decode_cbor_map_to_json(datum &d, buffer_stream &buf, vocabulary *v) {
    cbor_to_json_translator tr{v};

    if (lookahead<cbor::initial_byte> ib{d}) {
        switch (ib.value.major_type()) {
        case cbor::map_type:
            {
                cbor::map tmp{d};
                if (d.is_null()) { return false; }
                d = ib.advance();

                json_object map{&buf};
                bool success = tr.decode_cbor_map_to_json(d, map);
                map.close();
                if (!success) { return false; }
            }
            break;
        default:
            return false;
        }
    }
    return true;
}


/// decode the sequence of CBOR items in the \ref datum \param d,
/// and print a human-readable description of the items to \param f.
///
/// \return `true if all of the items in \param d could be
/// decoded, and `false` otherwise
///
static inline bool decode_fprint_json(datum d, FILE *f, vocabulary *v=nullptr) {

    output_buffer<2048> buf;
    bool result = decode_cbor_map_to_json(d, buf, v);
    buf.write_line(f);
    return result;
}


#endif // CBOR_OBJECT_HPP
