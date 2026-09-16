// cbor_object.hpp

#ifndef CBOR_OBJECT_HPP
#define CBOR_OBJECT_HPP

#include "datum.h"
#include "cbor.hpp"
#include "fdc.hpp"                // for cbor_fingerprint::encode_fingerprint()
#include "static_dict.hpp"
#include "json_object.h"
#include "null_terminated_string.hpp"
#include "utf8.hpp"
#include <limits>
#include <optional>
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

    static writeable &create_named_map(null_terminated_string key, cbor_object &o) {
        cbor::text_string{key.c_str()}.write(o.m);
        return o.m;
    }

    static writeable &create_named_map(uint64_t k, cbor_object &o) {
        cbor::uint64{k}.write(o.m);
        return o.m;
    }

    static writeable &create_named_map(datum key, cbor_object &o) {
        writeable &w = o.m;
        if (!key.is_readable()) {
            w.set_null();
            return w;
        }
        cbor::text_string::construct(key).write(o.m);
        return w;
    }

    friend class cbor_array;

    template <size_t N> friend class cbor_object_compact;

public:
    using array_type = cbor_array;   // companion array type (enables 1-param write<>)

    cbor_object(writeable &w) : m{w} { }

    cbor_object(cbor_object &o, null_terminated_string key) : m{create_named_map(key, o)} { }

    cbor_object(cbor_object &o, uint64_t k) : m{create_named_map(k, o)} { }

    cbor_object(cbor_object &o, datum key) : m{create_named_map(key, o)} { }

    cbor_object(cbor_object &o) : m{o.get_writeable()} { }

    template <size_t N>
    cbor_object(cbor_object_compact<N> &o, null_terminated_string key);

    cbor_object(cbor_array &a);

    void print_key_uint(null_terminated_string key, uint64_t value) {
        cbor::text_string{key.c_str()}.write(m);
        cbor::uint64{value}.write(m);
    }

    void print_key_string(null_terminated_string key, const char *str) {
        cbor::text_string{key.c_str()}.write(m);
        cbor::text_string{str}.write(m);
    }

    void print_key_string(null_terminated_string key, datum d) {
        if (d.is_readable()) {
            cbor::text_string{key.c_str()}.write(m);
            cbor::text_string::construct(d).write(m);
        }
    }

    void print_key_string(datum key, datum value) {
        if (key.is_readable() && value.is_readable()) {
            cbor::text_string::construct(key).write(m);
            cbor::text_string::construct(value).write(m);
        }
    }

    void print_key_hex(null_terminated_string key, datum bytes) {
        if (bytes.is_readable()) {
            cbor::text_string{key.c_str()}.write(m);
            cbor::byte_string::construct(bytes).write(m);
        }
    }

    void print_key_bool(null_terminated_string key, bool b) {
        cbor::text_string{key.c_str()}.write(m);
        cbor::initial_byte{cbor::simple_or_float_type, b ? cbor::initial_byte::True : cbor::initial_byte::False}.write(m);
    }

    void print_key_null(null_terminated_string key) {
        cbor::text_string{key.c_str()}.write(m);
        cbor::initial_byte{cbor::simple_or_float_type, cbor::initial_byte::null}.write(m);
    }

    void close() { m.close(); }

    writeable &get_writeable() { return m; }

};

class cbor_array {
    cbor::output::array a;

    static writeable &create_named_array(null_terminated_string key, cbor_object &o) {
        cbor::text_string{key.c_str()}.write(o.m);
        return o.m;
    }

    friend class cbor_object;

public:

    cbor_array(cbor_object &o, null_terminated_string key) : a{create_named_array(key, o)} { }


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

    void print_uint16_hex(uint16_t value) {
        char buf[4];
        buf[0] = hex_table[(value & 0xf000) >> 12];
        buf[1] = hex_table[(value & 0x0f00) >> 8];
        buf[2] = hex_table[(value & 0x00f0) >> 4];
        buf[3] = hex_table[value & 0x000f];
        datum d{(const uint8_t *)buf, (const uint8_t *)buf + 4};
        cbor::text_string::construct(d).write(a);
    }

    void print_uint(uint64_t value) {
        cbor::uint64{value}.write(a);
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
    cbor_object_compact(cbor_object_compact<M> &o, null_terminated_string key, const static_dictionary<N> &d) : cbor_object{o,key}, dict{d} {}

    // ~cbor_object_compact() { close(); }

    void print_key_uint(null_terminated_string key, uint64_t value) {
        cbor::uint64{dict.index(key.c_str())}.write(m);
        cbor::uint64{value}.write(m);
    }

    void print_key_string(null_terminated_string key, const char *str) {
        cbor::uint64{dict.index(key.c_str())}.write(m);
        cbor::text_string{str}.write(m);
    }

    void print_key_string(size_t idx, const char *str) {
        cbor::uint64{idx}.write(m);
        cbor::text_string{str}.write(m);
    }

    void print_key_hex(null_terminated_string key, datum bytes) {
        cbor::uint64{dict.index(key.c_str())}.write(m);
        cbor::byte_string::construct(bytes).write(m);
    }

    void print_key_float(null_terminated_string key, datum bytes) {
        cbor::uint64{dict.index(key.c_str())}.write(m);
        cbor::byte_string::construct(bytes).write(m);
    }

    void print_key_bool(null_terminated_string key, bool b) {
        cbor::uint64{dict.index(key.c_str())}.write(m);
        cbor::initial_byte{cbor::simple_or_float_type, b ? cbor::initial_byte::True : cbor::initial_byte::False}.write(m);
    }

    void print_key_null(null_terminated_string key) {
        cbor::uint64{dict.index(key.c_str())}.write(m);
        cbor::initial_byte{cbor::simple_or_float_type, cbor::initial_byte::null}.write(m);
    }

};

template <size_t N>
cbor_object::cbor_object(cbor_object_compact<N> &o, null_terminated_string key) : m{create_named_map(o.dict.index(key.c_str()), o)} { }



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

    null_terminated_string word(size_t idx) const {
        if (idx < a.size()) {
            return null_terminated_string::assume(a[idx].c_str());
        }
        return "UNKNOWN";  // note: could report unknown integer value as string
    }

};

#include "json_object.h"
#include "utf8.hpp"

/// report to \param f a tag 18000 whose content this build could not decode as a
/// fingerprint, and which the translator therefore dropped.  \param content is
/// the tag's content bytes, without the three-byte tag head. \param content past 189 bytes
/// is cut at the buffer and marked "(truncated)".
///
static inline void fprint_dropped_npf_tag(FILE *f, const datum &content) {
    output_buffer<256> b;
    b.raw_as_base64(content.data, content.data_end - content.data);
    b.add_null();
    fprintf(f, "warning: CBOR tag 18000 found, content dropped: %s%s\n",
            b.data(), b.is_truncated() ? "\" (truncated)" : "");
}

class cbor_to_json_translator {
    const vocabulary *keys;
    FILE *warn;      // where to report a dropped tag; nullptr is silent
    data_buffer<fingerprint::MAX_FP_STR_LEN> fp_buf;

    enum class type { key, value };

    /// Null-terminate the buffer and return a string wrapper over the contents.
    ///
    /// A null optional indicates that the buffer was truncated or could not be
    /// terminated in bounds.
    ///
    template <size_t N>
    static std::optional<null_terminated_string> null_terminate(output_buffer<N> &buf) {
        datum terminated{buf.null_terminate_and_get_datum()};
        if (terminated.is_null()) {
            return std::nullopt;
        }
        return null_terminated_string::assume(reinterpret_cast<const char *>(terminated.data));
    }

public:

    cbor_to_json_translator() : keys{nullptr}, warn{nullptr} { }

    cbor_to_json_translator(const vocabulary *v, FILE *w=nullptr) : keys{v}, warn{w} { }

    inline bool decode_cbor_array_to_json(datum &d, json_array &a, size_t depth = 0);

    /// decodes an indefinite-length cbor map body into \param o, consuming the
    /// terminating break byte.
    ///
    inline bool decode_cbor_map_to_json(datum &d, json_object &o, size_t depth = 0) {

        constexpr size_t max_recursion_depth = 256;
        if (depth > max_recursion_depth) {
            d.set_null();
            return false;
        }

        type expected_type = type::key;
        std::optional<null_terminated_string> key;

        // CBOR text keys are JSON-escaped into this fixed-size buffer.  An
        // escaped key that does not fit is rejected rather than truncated:
        // truncation can produce malformed JSON or collide with another key.
        //
        output_buffer<128> key_buf;

        while (d.is_readable()) {
            if (lookahead<cbor::initial_byte> ib{d}) {

                if (expected_type == type::key) { // store key for use with next value
                    switch (ib.value.major_type()) {

                    case cbor::unsigned_integer_type:
                        {
                            cbor::uint64 tmp{d};
                            if (d.is_null()) { return false; }
                            if (tmp.value() > std::numeric_limits<uint16_t>::max()) {
                                d.set_null();
                                return false;
                            }
                            if (keys == nullptr) {
                                key_buf.reset();
                                key_buf.write_uint16(tmp.value());
                                key = null_terminate(key_buf);
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
                            key = null_terminate(key_buf);
                        }
                        break;
                    case cbor::simple_or_float_type:
                        if (ib.value.value() == 0xff) {
                            d = ib.advance();
                            return true;      // end of map
                        }
                        [[fallthrough]];
                    default:
                        return false;
                    }

                    if (!key) {
                        d.set_null();   // an unusable key makes the whole map undecodable
                        return false;
                    }
                    expected_type = type::value;

                } else if (expected_type == type::value) {

                    null_terminated_string json_key = *key;
                    switch (ib.value.major_type()) {
                    case cbor::unsigned_integer_type:
                        {
                            cbor::uint64 tmp{d};
                            if (d.is_null()) { return false; }
                            o.print_key_uint(json_key, tmp.value());
                        }
                        break;
                    case cbor::byte_string_type:
                        {
                            cbor::byte_string tmp = cbor::byte_string::decode(d);
                            if (d.is_null()) { return false; }
                            o.print_key_hex(json_key, tmp.value());
                        }
                        break;
                    case cbor::text_string_type:
                        {
                            cbor::text_string tmp = cbor::text_string::decode(d);
                            if (d.is_null()) { return false; }
                            o.print_key_json_string(json_key, tmp.value());
                        }
                        break;
                    case cbor::array_type:
                        {
                            cbor::array tmp{d};
                            if (d.is_null()) { return false; }
                            json_array a{o, json_key};
                            bool success = decode_cbor_array_to_json(d, a, depth + 1);
                            a.close();
                            if (!success) { return false; }
                        }
                        break;
                    case cbor::map_type:
                        {
                            cbor::map tmp{d};
                            if (d.is_null()) { return false; }
                            d = ib.advance();
                            json_object map{o, json_key};
                            bool success = decode_cbor_map_to_json(d, map, depth + 1);
                            map.close();
                            if (!success) { return false; }
                        }
                        break;
                    case cbor::tagged_item_type:
                        {
                            cbor::tag tmp{d};
                            if (d.is_null()) { return false; }
                            if (tmp.value() == tag_npf_fingerprint) {
                                datum trial{d};          // a copy, so d survives a failed decode
                                fp_buf.reset();
                                cbor_fingerprint::decode_cbor_fingerprint(trial, fp_buf);
                                if (trial.is_not_null() and fp_buf.is_not_empty()) {
                                    d = trial;
                                    o.print_key_json_string(json_key, fp_buf.contents());
                                    break;
                                }
                            }
                            const uint8_t *start = d.data;
                            cbor::skip_cbor_value(d, depth + 1);
                            if (d.is_null()) { return false; }
                            datum content{start, d.data};
                            if (tmp.value() == tag_npf_fingerprint) {
                                // dropped: walked as opaque bytes, nothing written
                                if (warn) { fprint_dropped_npf_tag(warn, content); }
                            } else {
                                // the tag number is the key and base64 of the
                                // tag content is the value
                                output_buffer<24> tag_buf;   // 2^64-1 is 20 digits
                                tag_buf.snprintf("%" PRIu64, tmp.value());
                                std::optional<null_terminated_string> tag_key = null_terminate(tag_buf);
                                if (!tag_key) { d.set_null(); return false; }
                                json_object t{o, json_key};
                                t.print_key_base64(*tag_key, content);
                                t.close();
                            }
                        }
                        break;
                    case cbor::simple_or_float_type:
                        if (ib.value.value() == 0xff) {
                            return false;
                        } else if (ib.value.additional_info() == cbor::initial_byte::True) {
                            o.print_key_bool(json_key, true);
                            d = ib.advance();
                            break;
                        } else if (ib.value.additional_info() == cbor::initial_byte::False) {
                            o.print_key_bool(json_key, false);
                            d = ib.advance();
                            break;
                        } else if (ib.value.additional_info() == cbor::initial_byte::null) {
                            o.print_key_null(json_key);
                            d = ib.advance();
                            break;
                        }
                        [[fallthrough]];
                    default:
                        return false;
                    }

                    key.reset();
                    expected_type = type::key;
                }

            } else {
                return false;  // could not read initial byte
            }

        }

        d.set_null();   // the map was not terminated by a break byte
        return false;
    }

};

inline bool cbor_to_json_translator::decode_cbor_array_to_json(datum &d, json_array &a, size_t depth) {

    constexpr size_t max_recursion_depth = 256;
    if (depth > max_recursion_depth) {
        d.set_null();
        return false;
    }

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
                    bool success = decode_cbor_array_to_json(tmp, inner_array, depth + 1);
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
                    bool success = decode_cbor_map_to_json(d, map, depth + 1);
                    map.close();
                    if (!success) { return false; }
                }
                break;
            case cbor::tagged_item_type:
                {
                    cbor::tag tmp{d};
                    if (d.is_null()) { return false; }
                    if (tmp.value() == tag_npf_fingerprint) {
                        datum trial{d};                  // a copy, so d survives a failed decode
                        fp_buf.reset();
                        cbor_fingerprint::decode_cbor_fingerprint(trial, fp_buf);
                        if (trial.is_not_null() and fp_buf.is_not_empty()) {
                            d = trial;
                            a.print_json_string(fp_buf.contents());
                            break;
                        }
                    }
                    const uint8_t *start = d.data;
                    cbor::skip_cbor_value(d, depth + 1);
                    if (d.is_null()) { return false; }
                    datum content{start, d.data};
                    if (tmp.value() == tag_npf_fingerprint) {
                        // dropped: walked as opaque bytes, nothing written
                        if (warn) { fprint_dropped_npf_tag(warn, content); }
                    } else {
                        output_buffer<24> tag_buf;       // 2^64-1 is 20 digits
                        tag_buf.snprintf("%" PRIu64, tmp.value());
                        std::optional<null_terminated_string> tag_key = null_terminate(tag_buf);
                        if (!tag_key) { d.set_null(); return false; }
                        json_object t{a};
                        t.print_key_base64(*tag_key, content);
                        t.close();
                    }
                }
                break;
            case cbor::simple_or_float_type:
                if (ib.value.value() == 0xff) {
                    d = ib.advance();
                    return true;                         // end of array
                } else if (ib.value.additional_info() == cbor::initial_byte::True) {
                    a.print_bool(true);
                    d = ib.advance();
                    break;
                } else if (ib.value.additional_info() == cbor::initial_byte::False) {
                    a.print_bool(false);
                    d = ib.advance();
                    break;
                } else if (ib.value.additional_info() == cbor::initial_byte::null) {
                    a.print_null();
                    d = ib.advance();
                    break;
                }
                [[fallthrough]];
            default:
                return false;
            }
        }
    }
    d.set_null();   // an indefinite-length array must be terminated by a break
    return false;   // byte; reaching here means the input ended before one
}


static inline bool decode_cbor_map_to_json(datum &d, buffer_stream &buf, vocabulary *v,
                                           FILE *warn=nullptr) {
    cbor_to_json_translator tr{v, warn};

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

// LCOV_EXCL_START

/// compare the outcome of a cbor to json translation against what was expected,
/// and report any difference to \param f.
///
/// \param buf      holds the json that the translation produced
/// \param result   the value that the translator returned
/// \param leftover the number of bytes that it left unconsumed, or -1 if it
///                 nulled the datum
///
/// \return `true` if the translation matched in every respect, and `false`
/// otherwise
///
static inline bool check_translation(const char *name,
                                     const output_buffer<2048> &buf,
                                     bool result,
                                     ssize_t leftover,
                                     const char *expected_json,
                                     bool expected_result,
                                     ssize_t expected_leftover,
                                     FILE *f) {

    datum output{(const uint8_t *)buf.data(), (const uint8_t *)buf.data() + buf.content_size()};
    datum expected{(const uint8_t *)expected_json, (const uint8_t *)expected_json + strlen(expected_json)};

    if (result != expected_result or leftover != expected_leftover or output.cmp(expected) != 0) {
        if (f) {
            fprintf(f, "ERROR: cbor to json translation failed (%s)\n", name);
            fprintf(f, "returned:   %s, expected %s\n",
                    result ? "true" : "false", expected_result ? "true" : "false");
            fprintf(f, "unconsumed: %zd bytes, expected %zd\n", leftover, expected_leftover);
            fprintf(f, "json:       "); output.fprint(f);   fputc('\n', f);
            fprintf(f, "expected:   "); expected.fprint(f); fputc('\n', f);
        }
        return false;
    }
    return true;
}

/// translate the body of the indefinite-length cbor array in \param input into
/// json, and compare the result against \param expected_json.
///
/// \param expected_result   the value that the translator must return
/// \param expected_leftover the number of bytes that it must leave unconsumed
///
/// \return `true` if the translation matched in every respect, and `false`
/// otherwise
///
static inline bool test_cbor_array_to_json(const char *name,
                                           datum input,
                                           const char *expected_json,
                                           bool expected_result,
                                           ssize_t expected_leftover,
                                           FILE *f=nullptr) {

    output_buffer<2048> buf;
    cbor_to_json_translator translator{nullptr};

    cbor::array top{input};             // consumes the initial byte
    if (input.is_null()) { return false; }

    json_array a{&buf};
    bool result = translator.decode_cbor_array_to_json(input, a);
    a.close();

    ssize_t leftover = input.is_null() ? -1 : (ssize_t)input.length();
    return check_translation(name, buf, result, leftover,
                             expected_json, expected_result, expected_leftover, f);
}

/// translate the cbor map in \param input into json through the
/// decode_cbor_map_to_json() entry point, and compare the result against
/// \param expected_json.
///
/// \param expected_result   the value that the translator must return
/// \param expected_leftover the number of bytes that it must leave unconsumed
///
/// \return `true` if the translation matched in every respect, and `false`
/// otherwise
///
static inline bool test_cbor_map_to_json(const char *name,
                                         datum input,
                                         const char *expected_json,
                                         bool expected_result,
                                         ssize_t expected_leftover,
                                         FILE *f=nullptr) {

    output_buffer<2048> buf;
    bool result = decode_cbor_map_to_json(input, buf, nullptr);

    ssize_t leftover = input.is_null() ? -1 : (ssize_t)input.length();
    return check_translation(name, buf, result, leftover,
                             expected_json, expected_result, expected_leftover, f);
}

static inline bool cbor_object_unit_test(FILE *f=nullptr) {

    output_buffer<1> empty_buf;
    datum empty_datum{empty_buf.get_datum()};
    if (empty_datum.is_null()) {
        if (f) {
            fprintf(f, "test get_datum empty buffer failed\n");
        }
        return false;
    }
    datum empty_datum_with_null{empty_buf.null_terminate_and_get_datum()};
    if (empty_datum_with_null.is_null()
        || empty_datum_with_null.length() != 1
        || empty_datum_with_null.data[0] != '\0') {
        if (f) {
            fprintf(f, "test null_terminate_and_get_datum empty buffer failed\n");
        }
        return false;
    }
    auto empty_view = empty_datum.get_string_view();
    if (empty_view.data() == nullptr || empty_view.length() != 0) {
        if (f) {
            fprintf(f, "test get_string_view empty buffer failed\n");
        }
        return false;
    }

    output_buffer<4> truncated_buf;
    truncated_buf.puts("abcd");
    datum truncated_datum{truncated_buf.get_datum()};
    if (truncated_datum.is_not_null()) {
        if (f) {
            fprintf(f, "test get_datum truncated buffer failed\n");
        }
        return false;
    }

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
    cbor_object o{data_buf};
    o.print_key_string("key", "value");
    o.print_key_string("another_key", "another_value");
    {
        cbor_object n{o, "nested"};
        n.print_key_string("day", "Monday");
        n.print_key_string("month", "April");
        {
            cbor_object nn{n, "double_nested"};
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

    // An oversized text key must fail translation rather than be silently
    // shortened to the 127 bytes available in the key buffer.  Silent
    // truncation can produce malformed JSON or make distinct CBOR keys
    // collide in the JSON object.
    //
    std::array<uint8_t,133> oversized_key_map;
    oversized_key_map[0] = 0xbf;                                // {
    oversized_key_map[1] = 0x78;                                //   text string,
    oversized_key_map[2] = 128;                                 //   128 bytes
    for (size_t i = 0; i < 128; i++) {
        oversized_key_map[3 + i] = 'a';
    }
    oversized_key_map[131] = 0x01;                               //   1
    oversized_key_map[132] = 0xff;                               // }

    output_buffer<2048> translated;
    datum oversized_key_input{oversized_key_map};
    bool translated_ok = decode_cbor_map_to_json(oversized_key_input,
                                                  translated, nullptr);
    if (translated_ok || translated.get_string() != "{}") {
        if (f) {
            fprintf(f, "oversized CBOR key was not rejected\n");
        }
        return false;
    }

    // cbor to json translation
    //
    // Each case is one complete cbor item, the json that it must translate to,
    // the value that the translator must return, and the number of bytes that
    // it must leave unconsumed.  Tag 18000 (0xd94650) is the NPF fingerprint
    // tag; tag 999 (0xd903e7) and tag 251 (0xd8fb) are not registered.  An
    // undecodable fingerprint is dropped: the tag content is walked as opaque
    // bytes and nothing is written for it.  Any other unrecognized tag is
    // rendered as {"<tag number>":"<base64>"}, where the base64 covers the tag's
    // content bytes exactly.
    //
    // The 24 bytes 0xbf01bf019f420303421301d8fb9f42000042000affffffff, which
    // appear in three of the cases below, are the cbor encoding of the
    // fingerprint tls/1/(0303)(1301)[(0000)(000a)].
    //
    bool translation_tests_passed = true;

    // a registered fingerprint tag renders as a fingerprint string, and the
    // element after it is still found
    //
    std::array<uint8_t,30> known_fp{
        0x9f,                                                   // [
          0xd9, 0x46, 0x50,                                     //   tag(18000)
            0xbf, 0x01, 0xbf, 0x01,                             //     {1: {1:
              0x9f, 0x42, 0x03, 0x03, 0x42, 0x13, 0x01,         //       [0303, 1301,
                0xd8, 0xfb,                                     //         tag(251)
                  0x9f, 0x42, 0x00, 0x00, 0x42, 0x00, 0x0a,     //           [0000, 000a
                  0xff,                                         //           ]
              0xff,                                             //       ]
            0xff, 0xff,                                         //     }}
          0x01,                                                 //   1
        0xff                                                    // ]
    };
    translation_tests_passed &=
        test_cbor_array_to_json("known fingerprint tag, with a following element",
                          datum{known_fp},
                          "[\"tls/1/(0303)(1301)[(0000)(000a)]\",1]", true, 0, f);

    // an unknown fingerprint type (0x1863 is 99) is not decodable as a
    // fingerprint, so the tag and its content are dropped, leaving the array
    // empty
    //
    std::array<uint8_t,30> unknown_fp_type{
        0x9f,                                                   // [
          0xd9, 0x46, 0x50,                                     //   tag(18000)
            0xbf, 0x18, 0x63, 0xbf, 0x01,                       //     {99: {1:
              0x9f, 0x42, 0x03, 0x03, 0x42, 0x13, 0x01,         //       [0303, 1301,
                0xd8, 0xfb,                                     //         tag(251)
                  0x9f, 0x42, 0x00, 0x00, 0x42, 0x00, 0x0a,     //           [0000, 000a
                  0xff,                                         //           ]
              0xff,                                             //       ]
            0xff, 0xff,                                         //     }}
        0xff                                                    // ]
    };
    translation_tests_passed &=
        test_cbor_array_to_json("unknown fingerprint type",
                          datum{unknown_fp_type},
                          "[]", true, 0, f);

    // an unknown format version (7 in place of 1) likewise falls back
    //
    std::array<uint8_t,29> unknown_fp_version{
        0x9f,                                                   // [
          0xd9, 0x46, 0x50,                                     //   tag(18000)
            0xbf, 0x01, 0xbf, 0x07,                             //     {1: {7:
              0x9f, 0x42, 0x03, 0x03, 0x42, 0x13, 0x01,         //       [0303, 1301,
                0xd8, 0xfb,                                     //         tag(251)
                  0x9f, 0x42, 0x00, 0x00, 0x42, 0x00, 0x0a,     //           [0000, 000a
                  0xff,                                         //           ]
              0xff,                                             //       ]
            0xff, 0xff,                                         //     }}
        0xff                                                    // ]
    };
    translation_tests_passed &=
        test_cbor_array_to_json("unknown fingerprint format version",
                          datum{unknown_fp_version},
                          "[]", true, 0, f);

    // a randomized fingerprint, whose label the decoder must consume
    //
    std::array<uint8_t,13> randomized_fp{
        0x9f,                                                   // [
          0xd9, 0x46, 0x50,                                     //   tag(18000)
            0xbf, 0x01, 0xbf, 0x01, 0x01, 0xff, 0xff,           //     {1: {1: randomized}}
          0x05,                                                 //   5
        0xff                                                    // ]
    };
    translation_tests_passed &=
        test_cbor_array_to_json("randomized fingerprint, with a following element",
                          datum{randomized_fp},
                          "[\"tls/1/randomized\",5]", true, 0, f);

    // an unknown tag in array element position, holding an array
    //
    std::array<uint8_t,9> unknown_tag_in_array{
        0x9f,                                                   // [
          0xd9, 0x03, 0xe7,                                     //   tag(999)
            0x9f, 0x01, 0xff,                                   //     [1]
          0x02,                                                 //   2
        0xff                                                    // ]
    };
    translation_tests_passed &=
        test_cbor_array_to_json("unknown tag in an array, with a following element",
                          datum{unknown_tag_in_array},
                          "[{\"999\":\"nwH/\"},2]", true, 0, f);

    // an unknown tag in map value position, holding an unsigned integer, with a
    // key/value pair on either side of it
    //
    std::array<uint8_t,11> unknown_tag_in_map{
        0xbf,                                                   // {
          0x01, 0x01,                                           //   1: 1,
          0x02, 0xd9, 0x03, 0xe7, 0x01,                          //   2: tag(999)1,
          0x03, 0x03,                                           //   3: 3
        0xff                                                    // }
    };
    translation_tests_passed &=
        test_cbor_map_to_json("unknown tag as a map value, with siblings",
                          datum{unknown_tag_in_map},
                          "{\"1\":1,\"2\":{\"999\":\"AQ==\"},\"3\":3}", true, 0, f);

    // a registered fingerprint tag in map value position
    //
    std::array<uint8_t,32> known_fp_in_map{
        0xbf,                                                   // {
          0x01,                                                 //   1:
          0xd9, 0x46, 0x50,                                     //   tag(18000)
            0xbf, 0x01, 0xbf, 0x01,                             //     {1: {1:
              0x9f, 0x42, 0x03, 0x03, 0x42, 0x13, 0x01,         //       [0303, 1301,
                0xd8, 0xfb,                                     //         tag(251)
                  0x9f, 0x42, 0x00, 0x00, 0x42, 0x00, 0x0a,     //           [0000, 000a
                  0xff,                                         //           ]
              0xff,                                             //       ]
            0xff, 0xff,                                         //     }}
          0x02, 0x02,                                           //   2: 2
        0xff                                                    // }
    };
    translation_tests_passed &=
        test_cbor_map_to_json("known fingerprint tag as a map value, with a sibling",
                          datum{known_fp_in_map},
                          "{\"1\":\"tls/1/(0303)(1301)[(0000)(000a)]\",\"2\":2}", true, 0, f);

    // a tag head with no content after it.  skip_cbor_value() refuses the break
    // byte that follows, because a break is not a data item (RFC 8949 Sec.
    // 3.2.1), so the failure is detected before any json is opened and the datum
    // is left null rather than partly consumed.
    //
    std::array<uint8_t,5> truncated_tag{
        0x9f,                                                   // [
          0xd9, 0x03, 0xe7,                                     //   tag(999)
        0xff                                                    // ]
    };
    translation_tests_passed &=
        test_cbor_array_to_json("tag head with no content",
                          datum{truncated_tag},
                          "[]", false, -1, f);

    // an unknown tag number above 2^16, which the committed code rendered as a
    // json number and this code renders as a key
    //
    std::array<uint8_t,8> tag_above_16_bits{
        0x9f,                                                   // [
          0xda, 0x00, 0x01, 0x11, 0x70,                         //   tag(70000)
            0x01,                                               //     1
        0xff                                                    // ]
    };
    translation_tests_passed &=
        test_cbor_array_to_json("unknown tag number above 2^16",
                          datum{tag_above_16_bits},
                          "[{\"70000\":\"AQ==\"}]", true, 0, f);

    // an unknown tag holding a definite-length array.
    std::array<uint8_t,8> tag_holding_definite_array{
        0x9f,                                                   // [
          0xd9, 0x03, 0xe7,                                     //   tag(999)
            0x82, 0x01, 0x02,                                   //     [1, 2]
        0xff                                                    // ]
    };
    translation_tests_passed &=
        test_cbor_array_to_json("unknown tag holding a definite-length array",
                          datum{tag_holding_definite_array},
                          "[{\"999\":\"ggEC\"}]", true, 0, f);

    // a tag head that uses the indefinite-length additional info, which carries
    // no argument at all, so there is no tag number to read (RFC 8949 Sec. 3.3)
    //
    std::array<uint8_t,4> tag_head_ai_31{
        0x9f,                                                   // [
          0xdf,                                                 //   tag(-)
            0x01,                                               //     1
        0xff                                                    // ]
    };
    translation_tests_passed &=
        test_cbor_array_to_json("tag head with indefinite-length additional info",
                          datum{tag_head_ai_31},
                          "[]", false, -1, f);

    // a tag head that uses a reserved additional info, which makes the item
    // ill formed rather than a tag numbered zero
    //
    std::array<uint8_t,4> tag_head_ai_28{
        0x9f,                                                   // [
          0xdc,                                                 //   tag(-)
            0x01,                                               //     1
        0xff                                                    // ]
    };
    translation_tests_passed &=
        test_cbor_array_to_json("tag head with reserved additional info",
                          datum{tag_head_ai_28},
                          "[]", false, -1, f);

    // an indefinite-length text string, which this interface does not produce.
    // Its head carries no length, so it is rejected rather than read as a
    // zero-length string whose chunk becomes the next element.
    //
    std::array<uint8_t,6> indefinite_text_string{
        0x9f,                                                   // [
          0x7f, 0x61, 0x61, 0xff,                               //   (_ "a")
        0xff                                                    // ]
    };
    translation_tests_passed &=
        test_cbor_array_to_json("indefinite-length text string",
                          datum{indefinite_text_string},
                          "[]", false, -1, f);

    // reserved additional info on the head of an unknown tag's content, which
    // skip_cbor_value() has to reject for the major types that carry a count or
    // no argument at all.  A definite-length array or map head with a reserved
    // additional info declares no count, and a major type 7 head with one
    // declares no payload, so none of the three can be advanced past.
    //
    std::array<uint8_t,6> reserved_array_head{
        0x9f,                                                   // [
          0xd9, 0x03, 0xe7,                                     //   tag(999)
            0x9c,                                               //     array(-)
        0xff                                                    // ]
    };
    translation_tests_passed &=
        test_cbor_array_to_json("reserved additional info on an array head",
                          datum{reserved_array_head},
                          "[]", false, -1, f);

    std::array<uint8_t,6> reserved_map_head{
        0x9f,                                                   // [
          0xd9, 0x03, 0xe7,                                     //   tag(999)
            0xbc,                                               //     map(-)
        0xff                                                    // ]
    };
    translation_tests_passed &=
        test_cbor_array_to_json("reserved additional info on a map head",
                          datum{reserved_map_head},
                          "[]", false, -1, f);

    std::array<uint8_t,6> reserved_simple_head{
        0x9f,                                                   // [
          0xd9, 0x03, 0xe7,                                     //   tag(999)
            0xfc,                                               //     simple(-)
        0xff                                                    // ]
    };
    translation_tests_passed &=
        test_cbor_array_to_json("reserved additional info on a simple value head",
                          datum{reserved_simple_head},
                          "[]", false, -1, f);

    // a one-byte simple value below 0x20, which is the long spelling of a value
    // that has to use the immediate form: f8 14 says what f4 already says.
    //
    std::array<uint8_t,7> simple_value_below_20{
        0x9f,                                                   // [
          0xd9, 0x03, 0xe7,                                     //   tag(999)
            0xf8, 0x14,                                         //     simple(20)
        0xff                                                    // ]
    };
    translation_tests_passed &=
        test_cbor_array_to_json("one-byte simple value below 0x20",
                          datum{simple_value_below_20},
                          "[]", false, -1, f);

    // 0x20 is the lowest simple value the one-byte form is allowed to carry
    //
    std::array<uint8_t,7> simple_value_at_20{
        0x9f,                                                   // [
          0xd9, 0x03, 0xe7,                                     //   tag(999)
            0xf8, 0x20,                                         //     simple(32)
        0xff                                                    // ]
    };
    translation_tests_passed &=
        test_cbor_array_to_json("one-byte simple value at 0x20",
                          datum{simple_value_at_20},
                          "[{\"999\":\"+CA=\"}]", true, 0, f);

    // a map with an odd number of items, so its last key has no value.  The break
    // lands where a value belongs, and if a value reader accepted it the map would
    // swallow the array's break as well and the whole input would look well formed.
    //
    std::array<uint8_t,10> map_with_orphan_key{
        0x9f,                                                   // [
          0xd9, 0x03, 0xe7,                                     //   tag(999)
            0xbf, 0x01, 0x02, 0x03,                             //     {1: 2, 3:
            0xff,                                               //     }
        0xff                                                    // ]
    };
    translation_tests_passed &=
        test_cbor_array_to_json("map with an orphan key",
                          datum{map_with_orphan_key},
                          "[]", false, -1, f);

    // the same map with the value its last key was missing, which has to keep working
    //
    std::array<uint8_t,11> map_with_paired_keys{
        0x9f,                                                   // [
          0xd9, 0x03, 0xe7,                                     //   tag(999)
            0xbf, 0x01, 0x02, 0x03, 0x04,                       //     {1: 2, 3: 4
            0xff,                                               //     }
        0xff                                                    // ]
    };
    translation_tests_passed &=
        test_cbor_array_to_json("map with an even number of items",
                          datum{map_with_paired_keys},
                          "[{\"999\":\"vwECAwT/\"}]", true, 0, f);

    // null and false in array element position, followed by an unsigned integer
    //
    std::array<uint8_t,5> simple_values{
        0x9f,                                                   // [
          0xf6,                                                 //   null,
          0xf4,                                                 //   false,
          0x01,                                                 //   1
        0xff                                                    // ]
    };
    translation_tests_passed &=
        test_cbor_array_to_json("null and false as array elements",
                          datum{simple_values},
                          "[null,false,1]", true, 0, f);

    // true in array element position, before another simple value and an
    // unsigned integer
    //
    std::array<uint8_t,5> true_in_array{
        0x9f,                                                   // [
          0xf5,                                                 //   true,
          0xf6,                                                 //   null,
          0x02,                                                 //   2
        0xff                                                    // ]
    };
    translation_tests_passed &=
        test_cbor_array_to_json("true as an array element",
                          datum{true_in_array},
                          "[true,null,2]", true, 0, f);

    // an array nested inside an array
    //
    std::array<uint8_t,6> nested_array{
        0x9f,                                                   // [
          0x9f, 0x01, 0x02, 0xff,                               //   [1, 2]
        0xff                                                    // ]
    };
    translation_tests_passed &=
        test_cbor_array_to_json("an array nested in an array",
                          datum{nested_array},
                          "[[1,2]]", true, 0, f);

    // an array whose elements are well formed but whose break byte is missing.
    // Only indefinite-length arrays are supported, so a break is required (RFC
    // 8949 Sec. 3.2.1) and running out of input is a truncation, not an end.
    //
    std::array<uint8_t,3> array_without_break{
        0x9f,                                                   // [
          0x01, 0x02                                            //   1, 2
    };
    translation_tests_passed &=
        test_cbor_array_to_json("array truncated before the break",
                          datum{array_without_break},
                          "[1,2]", false, -1, f);

    // an array head with nothing at all after it
    //
    std::array<uint8_t,1> empty_array_without_break{
        0x9f                                                    // [
    };
    translation_tests_passed &=
        test_cbor_array_to_json("empty array truncated before the break",
                          datum{empty_array_without_break},
                          "[]", false, -1, f);

    // a nested array in which neither the inner nor the outer break is present,
    // so the failure has to propagate out of the recursive call
    //
    std::array<uint8_t,4> nested_array_without_break{
        0x9f,                                                   // [
          0x9f, 0x01, 0x02                                      //   [1, 2
    };
    translation_tests_passed &=
        test_cbor_array_to_json("nested array truncated before the break",
                          datum{nested_array_without_break},
                          "[[1,2]]", false, -1, f);

    // a map holding one complete key/value pair but no break byte
    //
    std::array<uint8_t,3> map_without_break{
        0xbf,                                                   // {
          0x01, 0x01                                            //   1: 1
    };
    translation_tests_passed &=
        test_cbor_map_to_json("map truncated before the break",
                          datum{map_without_break},
                          "{\"1\":1}", false, -1, f);

    // a text key whose JSON-escaped form does not fit key_buf.  64 backslashes
    // double to 128 bytes, one more than the buffer holds with its null, and the
    // surviving key would end in a lone backslash that escapes the closing quote.
    //
    {
        std::array<uint8_t,69> escaped_key_too_long;
        escaped_key_too_long[0] = 0xbf;                         // {
        escaped_key_too_long[1] = 0x78;                         //   text string,
        escaped_key_too_long[2] = 64;                           //   64 bytes
        for (size_t i = 0; i < 64; i++) {
            escaped_key_too_long[3 + i] = '\\';                 //   all backslashes
        }
        escaped_key_too_long[67] = 0x01;                        //   1
        escaped_key_too_long[68] = 0xff;                        // }
        translation_tests_passed &=
            test_cbor_map_to_json("text key too long once escaped",
                              datum{escaped_key_too_long},
                              "{}", false, -1, f);
    }

    // a text key that needs no escaping and still does not fit: 128 bytes into a
    // buffer that holds 127.  This is the flavor that yields parseable json with a
    // silently shortened key, so two long keys sharing a prefix collide.
    //
    {
        std::array<uint8_t,133> key_too_long;
        key_too_long[0] = 0xbf;                                 // {
        key_too_long[1] = 0x78;                                 //   text string,
        key_too_long[2] = 128;                                  //   128 bytes
        for (size_t i = 0; i < 128; i++) {
            key_too_long[3 + i] = 'a';
        }
        key_too_long[131] = 0x01;                               //   1
        key_too_long[132] = 0xff;                               // }
        translation_tests_passed &=
            test_cbor_map_to_json("text key too long unescaped",
                              datum{key_too_long},
                              "{}", false, -1, f);
    }

    // an unsigned key above the 65535 that guideline 3 allows.  Rendering it
    // through write_uint16() would reduce it mod 65536, so 65536 would print as
    // "0" and collide with a sibling key of 0.
    //
    std::array<uint8_t,8> unsigned_key_out_of_range{
        0xbf,                                                   // {
          0x1a, 0x00, 0x01, 0x00, 0x00,                         //   65536:
          0x01,                                                 //   1
        0xff                                                    // }
    };
    translation_tests_passed &=
        test_cbor_map_to_json("unsigned key above 65535",
                          datum{unsigned_key_out_of_range},
                          "{}", false, -1, f);

    // the largest unsigned key guideline 3 allows, which has to keep working
    //
    std::array<uint8_t,6> unsigned_key_at_limit{
        0xbf,                                                   // {
          0x19, 0xff, 0xff,                                     //   65535:
          0x01,                                                 //   1
        0xff                                                    // }
    };
    translation_tests_passed &=
        test_cbor_map_to_json("unsigned key at 65535",
                          datum{unsigned_key_at_limit},
                          "{\"65535\":1}", true, 0, f);

    // an npf tag in map value position whose content this build cannot decode
    // as a fingerprint: the format version is 7.  The tag, its content and the
    // key that holds them are dropped, and the sibling after them survives.
    //
    std::array<uint8_t,32> unknown_fp_in_map{
        0xbf,                                                   // {
          0x01,                                                 //   1:
          0xd9, 0x46, 0x50,                                     //   tag(18000)
            0xbf, 0x01, 0xbf, 0x07,                             //     {1: {7:
              0x9f, 0x42, 0x03, 0x03, 0x42, 0x13, 0x01,         //       [0303, 1301,
                0xd8, 0xfb,                                     //         tag(251)
                  0x9f, 0x42, 0x00, 0x00, 0x42, 0x00, 0x0a,     //           [0000, 000a
                  0xff,                                         //           ]
              0xff,                                             //       ]
            0xff, 0xff,                                         //     }}
          0x02, 0x02,                                           //   2: 2
        0xff                                                    // }
    };
    translation_tests_passed &=
        test_cbor_map_to_json("undecodable fingerprint as a map value, with a sibling",
                          datum{unknown_fp_in_map},
                          "{\"2\":2}", true, 0, f);

    // the same input with a warning sink attached.  The json must be identical:
    // the sink only adds a diagnostic, which is how one consumer of this header
    // reports a dropped tag while another stays silent.
    //
    {
        output_buffer<2048> buf;
        datum input{unknown_fp_in_map};
        FILE *sink = tmpfile();
        bool result = decode_cbor_map_to_json(input, buf, nullptr, sink);
        ssize_t leftover = input.is_null() ? -1 : (ssize_t)input.length();

        char line[256] = { '\0' };
        if (sink != nullptr) {
            rewind(sink);
            if (fgets(line, sizeof(line), sink) == nullptr) { line[0] = '\0'; }
            fclose(sink);
        }
        const char *expected_line =
            "warning: CBOR tag 18000 found, content dropped: "
            "\"vwG/B59CAwNCEwHY+59CAABCAAr/////\"\n";

        translation_tests_passed &=
            check_translation("undecodable fingerprint, with a warning sink",
                              buf, result, leftover, "{\"2\":2}", true, 0, f);

        if (strcmp(line, expected_line) != 0) {
            if (f) {
                fprintf(f, "ERROR: the warning sink did not receive the dropped tag\n");
                fprintf(f, "written:  %s", line);
                fprintf(f, "expected: %s", expected_line);
            }
            translation_tests_passed = false;
        }
    }

    // input nested deeper than max_recursion_depth, which the depth guard must
    // reject rather than recurse to exhaustion.  The json in the buffer is one
    // bracket per level entered before the guard fired, so only the return
    // value and the nulled datum are checked here.
    //
    {
        std::array<uint8_t,260> deep_arrays;
        deep_arrays.fill(0x9f);                 // 260 nested arrays, never closed
        datum input{deep_arrays};
        output_buffer<2048> buf;
        cbor_to_json_translator translator{nullptr};
        cbor::array top{input};                 // consumes the initial byte
        json_array a{&buf};
        bool result = translator.decode_cbor_array_to_json(input, a);
        a.close();
        if (result or input.is_not_null()) {
            if (f) {
                fprintf(f, "ERROR: array nested past the recursion limit was not rejected\n");
            }
            translation_tests_passed = false;
        }
    }
    {
        std::array<uint8_t,600> deep_maps;
        for (size_t i = 0; i < deep_maps.size(); i += 2) {
            deep_maps[i] = 0xbf;                // 300 nested maps, never closed,
            deep_maps[i+1] = 0x01;              // each keyed on 1
        }
        datum input{deep_maps};
        output_buffer<2048> buf;
        if (decode_cbor_map_to_json(input, buf, nullptr) or input.is_not_null()) {
            if (f) {
                fprintf(f, "ERROR: map nested past the recursion limit was not rejected\n");
            }
            translation_tests_passed = false;
        }
    }

    if (!translation_tests_passed) {
        return false;
    }

    return true;
}
// LCOV_EXCL_STOP

#endif // CBOR_OBJECT_HPP
