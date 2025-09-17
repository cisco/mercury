// cbor_object.hpp

#ifndef CBOR_OBJECT_HPP
#define CBOR_OBJECT_HPP

#include "datum.h"
#include "cbor.hpp"
#include "fdc.hpp"                // for cbor_fingerprint::encode_fingerprint()
#include "static_dict.hpp"
#include "json_object.h"
#include "utf8.hpp"
#include <stdexcept>

constexpr uint64_t tag_npf_fingerprint = 0x4650; // application tag 18000, "FP"; NPF representation hint 

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

    cbor_object(cbor_object &o, uint64_t k) : m{create_named_map(k, o)} { }

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

    void print_key_string(const char *key, datum d) {
        if (d.is_readable()) {
            cbor::text_string{key}.write(m);
            cbor::text_string::construct(d).write(m);
        }
    }

    void print_key_hex(const char *key, datum bytes) {
        if (bytes.is_readable()) {
            cbor::text_string{key}.write(m);
            cbor::byte_string::construct(bytes).write(m);
        }
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

    void print_string(datum s) {
        if (s.is_readable()) {
            cbor::text_string::construct(s).write(a);
        }
    }

    void close() { a.close(); }

    writeable & get_writeable() { return a; }
};

inline cbor_object::cbor_object(cbor_array &outer) : m{outer.a} { }


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
        return "UNKNOWN";  // note: could report unknown integer value as string
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
                        fprintf(stderr, "remaining bytes in cbor data: ");
                        d.fprint_hex(stderr); fputc('\n', stderr); 
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
                            o.print_key_uint("tag", tmp.value());
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
                    if (tmp.value() == tag_npf_fingerprint) {
                        data_buffer<fingerprint::MAX_FP_STR_LEN> fp_out_buf;
                        cbor_fingerprint::decode_cbor_fingerprint(d, fp_out_buf);
                        a.print_json_string(fp_out_buf.contents());
                    } else {
                        a.print_uint(tmp.value());  // ??????????????????????
                    }
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
template <size_t N=2048>
static inline bool decode_fprint_json(datum d, FILE *f, vocabulary *v=nullptr) {

    output_buffer<N> buf;
    bool result = decode_cbor_map_to_json(d, buf, v);
    buf.write_line(f);
    return result;
}

static inline bool cbor_object_unit_test(FILE *f=nullptr) {

    // first test
    //
    dynamic_buffer data_buf{4096};
    cbor_object r{data_buf};
    {
        cbor_object fingerprints{r, "fingerprints"};
        fingerprints.print_key_string("tcp", "(7210)(020405b4)(04)(08)(01)(030307)");
        fingerprints.close();
    }
    r.print_key_string("src_ip", "10.0.2.15");
    r.print_key_string("dst_ip", "172.217.7.228");
    r.print_key_uint("protocol", 6);
    r.print_key_uint("src_port", 3759);
    r.print_key_uint("dst_port", 443);
    r.close();

    std::array<uint8_t,131> test1{
        0xbf, 0x6c, 0x66, 0x69, 0x6e, 0x67, 0x65, 0x72,
        0x70, 0x72, 0x69, 0x6e, 0x74, 0x73, 0xbf, 0x63,
        0x74, 0x63, 0x70, 0x78, 0x24, 0x28, 0x37, 0x32,
        0x31, 0x30, 0x29, 0x28, 0x30, 0x32, 0x30, 0x34,
        0x30, 0x35, 0x62, 0x34, 0x29, 0x28, 0x30, 0x34,
        0x29, 0x28, 0x30, 0x38, 0x29, 0x28, 0x30, 0x31,
        0x29, 0x28, 0x30, 0x33, 0x30, 0x33, 0x30, 0x37,
        0x29, 0xff, 0x66, 0x73, 0x72, 0x63, 0x5f, 0x69,
        0x70, 0x69, 0x31, 0x30, 0x2e, 0x30, 0x2e, 0x32,
        0x2e, 0x31, 0x35, 0x66, 0x64, 0x73, 0x74, 0x5f,
        0x69, 0x70, 0x6d, 0x31, 0x37, 0x32, 0x2e, 0x32,
        0x31, 0x37, 0x2e, 0x37, 0x2e, 0x32, 0x32, 0x38,
        0x68, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x63, 0x6f,
        0x6c, 0x06, 0x68, 0x73, 0x72, 0x63, 0x5f, 0x70,
        0x6f, 0x72, 0x74, 0x19, 0x0e, 0xaf, 0x68, 0x64,
        0x73, 0x74, 0x5f, 0x70, 0x6f, 0x72, 0x74, 0x19,
        0x01, 0xbb, 0xff
    };
    if (!data_buf.contents().equals(test1)) {
        if (f) {
            fprintf(f, "test 1 failed\n");
            data_buf.contents().fprint_hex(f); fputc('\n', f);
            decode_fprint_json(data_buf.contents(), f);
            data_buf.contents().fprint_c_array(f, "test2"); fputc('\n', f);
        }
        return false;
    }

    // second test
    //
    data_buf.reset();
    struct cbor_object o{data_buf};
    o.print_key_string("key", "value");
    o.print_key_string("another_key", "another_value");
    {
        struct cbor_object n{o, "nested"};
        n.print_key_string("day", "Monday");
        n.print_key_string("month", "April");
        {
            struct cbor_object nn{n, "double_nested"};
            nn.print_key_uint("two_plus_two", 5);
            nn.print_key_string("note", "for very large values of two");
            nn.close();
        }
        n.close();
    }
    o.print_key_string("addendum", "this is just to test commas");
    {
        cbor_array a{o, "numerology"};
        {
            cbor_object oa{a};
            oa.print_key_string("note", "the key value pair is wrapped in an object");
            oa.close();
        }
        {
            cbor_object oa{a};
            oa.print_key_string("foo", "bar");
            oa.close();
        }
        {
            cbor_object oa{a};
            oa.print_key_string("author", "Thomas Pynchon");
            oa.close();
        }
        {
            cbor_object oa{a};
            oa.print_key_string("title", "Gravity's Rainbow");
            oa.close();
        }
        {
            cbor_array nested_array{a};
            nested_array.print_string("this string is in a nested array");
            nested_array.close();
        }
        a.close();
    }
    o.print_key_bool("cbor_is_fun", true);
    o.print_key_null("latin word for none");
    o.close();
    std::array<uint8_t,367> test2{
        0xbf, 0x63, 0x6b, 0x65, 0x79, 0x65, 0x76, 0x61,
        0x6c, 0x75, 0x65, 0x6b, 0x61, 0x6e, 0x6f, 0x74,
        0x68, 0x65, 0x72, 0x5f, 0x6b, 0x65, 0x79, 0x6d,
        0x61, 0x6e, 0x6f, 0x74, 0x68, 0x65, 0x72, 0x5f,
        0x76, 0x61, 0x6c, 0x75, 0x65, 0x66, 0x6e, 0x65,
        0x73, 0x74, 0x65, 0x64, 0xbf, 0x63, 0x64, 0x61,
        0x79, 0x66, 0x4d, 0x6f, 0x6e, 0x64, 0x61, 0x79,
        0x65, 0x6d, 0x6f, 0x6e, 0x74, 0x68, 0x65, 0x41,
        0x70, 0x72, 0x69, 0x6c, 0x6d, 0x64, 0x6f, 0x75,
        0x62, 0x6c, 0x65, 0x5f, 0x6e, 0x65, 0x73, 0x74,
        0x65, 0x64, 0xbf, 0x6c, 0x74, 0x77, 0x6f, 0x5f,
        0x70, 0x6c, 0x75, 0x73, 0x5f, 0x74, 0x77, 0x6f,
        0x05, 0x64, 0x6e, 0x6f, 0x74, 0x65, 0x78, 0x1c,
        0x66, 0x6f, 0x72, 0x20, 0x76, 0x65, 0x72, 0x79,
        0x20, 0x6c, 0x61, 0x72, 0x67, 0x65, 0x20, 0x76,
        0x61, 0x6c, 0x75, 0x65, 0x73, 0x20, 0x6f, 0x66,
        0x20, 0x74, 0x77, 0x6f, 0xff, 0xff, 0x68, 0x61,
        0x64, 0x64, 0x65, 0x6e, 0x64, 0x75, 0x6d, 0x78,
        0x1b, 0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73,
        0x20, 0x6a, 0x75, 0x73, 0x74, 0x20, 0x74, 0x6f,
        0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x63, 0x6f,
        0x6d, 0x6d, 0x61, 0x73, 0x6a, 0x6e, 0x75, 0x6d,
        0x65, 0x72, 0x6f, 0x6c, 0x6f, 0x67, 0x79, 0x9f,
        0xbf, 0x64, 0x6e, 0x6f, 0x74, 0x65, 0x78, 0x2a,
        0x74, 0x68, 0x65, 0x20, 0x6b, 0x65, 0x79, 0x20,
        0x76, 0x61, 0x6c, 0x75, 0x65, 0x20, 0x70, 0x61,
        0x69, 0x72, 0x20, 0x69, 0x73, 0x20, 0x77, 0x72,
        0x61, 0x70, 0x70, 0x65, 0x64, 0x20, 0x69, 0x6e,
        0x20, 0x61, 0x6e, 0x20, 0x6f, 0x62, 0x6a, 0x65,
        0x63, 0x74, 0xff, 0xbf, 0x63, 0x66, 0x6f, 0x6f,
        0x63, 0x62, 0x61, 0x72, 0xff, 0xbf, 0x66, 0x61,
        0x75, 0x74, 0x68, 0x6f, 0x72, 0x6e, 0x54, 0x68,
        0x6f, 0x6d, 0x61, 0x73, 0x20, 0x50, 0x79, 0x6e,
        0x63, 0x68, 0x6f, 0x6e, 0xff, 0xbf, 0x65, 0x74,
        0x69, 0x74, 0x6c, 0x65, 0x71, 0x47, 0x72, 0x61,
        0x76, 0x69, 0x74, 0x79, 0x27, 0x73, 0x20, 0x52,
        0x61, 0x69, 0x6e, 0x62, 0x6f, 0x77, 0xff, 0x9f,
        0x78, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x73,
        0x74, 0x72, 0x69, 0x6e, 0x67, 0x20, 0x69, 0x73,
        0x20, 0x69, 0x6e, 0x20, 0x61, 0x20, 0x6e, 0x65,
        0x73, 0x74, 0x65, 0x64, 0x20, 0x61, 0x72, 0x72,
        0x61, 0x79, 0xff, 0xff, 0x6b, 0x63, 0x62, 0x6f,
        0x72, 0x5f, 0x69, 0x73, 0x5f, 0x66, 0x75, 0x6e,
        0xf5, 0x73, 0x6c, 0x61, 0x74, 0x69, 0x6e, 0x20,
        0x77, 0x6f, 0x72, 0x64, 0x20, 0x66, 0x6f, 0x72,
        0x20, 0x6e, 0x6f, 0x6e, 0x65, 0xf6, 0xff
    };
    if (!data_buf.contents().equals(test2)) {
        if (f) {
            fprintf(f, "test 2 failed\n");
            data_buf.contents().fprint_hex(f); fputc('\n', f);
            decode_fprint_json(data_buf.contents(), f);
            data_buf.contents().fprint_c_array(f, "test2"); fputc('\n', f);
        }
        return false;
    }


    return true;
}

#endif // CBOR_OBJECT_HPP
