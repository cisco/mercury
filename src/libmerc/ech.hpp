// ech.hpp
//
// encrypted client hello related classes

#ifndef ECH_HPP
#define ECH_HPP

#include "datum.h"
#include "hpke_params.h"
#include "json_object.h"
#include "json_string.hpp"

// An object of class opaque represents a TLS variable-length opaque
// data field, as described in RFC 8446.
//
template <typename T>
class opaque {
    encoded<T> length;
    datum elements;

    static_assert(std::is_unsigned_v<T>, "T must be an unsigned integer");

public:

    opaque(datum &d) : length{d}, elements{d, length} { }

    void write_json(json_object &o, const char *name) const {
        o.print_key_hex(name, elements);
    }

    datum get_value() const { return elements; }

    ssize_t get_length() const { return elements.length(); }
};


// Following draft-ietf-tls-esni-18:
//
//   opaque HpkePublicKey<1..2^16-1>;
//   uint16 HpkeKemId;  // Defined in RFC9180
//   uint16 HpkeKdfId;  // Defined in RFC9180
//   uint16 HpkeAeadId; // Defined in RFC9180
//
//   struct {
//       HpkeKdfId kdf_id;
//       HpkeAeadId aead_id;
//   } HpkeSymmetricCipherSuite;
//
class hpke_symmetric_cipher_suite {
    hpke::kdf<uint16_t> kdf_id;
    hpke::aead<uint16_t> aead_id;

public:

    hpke_symmetric_cipher_suite(datum &d) : kdf_id{d}, aead_id{d} { }

    void write_json(json_object &o) const {
        json_object wrapper{o, "hpke_symmetric_cipher_suite"};
        kdf_id.write_json(wrapper);
        aead_id.write_json(wrapper);
        wrapper.close();
    }

    void write_json(json_array &a) const {
        json_object wrapper{a};
        kdf_id.write_json(wrapper);
        aead_id.write_json(wrapper);
        wrapper.close();
    }

};

// Following draft-ietf-tls-esni-18:
//
//   struct {
//       uint8 config_id;
//       HpkeKemId kem_id;
//       HpkePublicKey public_key;
//       HpkeSymmetricCipherSuite cipher_suites<4..2^16-4>;
//   } HpkeKeyConfig;
//
class hpke_key_config {
    encoded<uint8_t> config_id;
    hpke::kem<uint16_t> kem_id;
    opaque<uint16_t> public_key;
    opaque<uint16_t> hpke_symmetric_cipher_suites;

public:

    hpke_key_config(datum &d) :
        config_id{d},
        kem_id{d},
        public_key{d},
        hpke_symmetric_cipher_suites{d}
    { }

    void write_json(json_object &o) const {
        json_object wrapper{o, "hpke_key_config"};
        wrapper.print_key_uint("config_id", config_id.value());
        kem_id.write_json(wrapper);
        public_key.write_json(wrapper, "public_key");

        datum tmp{hpke_symmetric_cipher_suites.get_value()};
        json_array a{wrapper, "hpke_symmetric_cipher_suite"};
        while (tmp.is_readable()) {
            hpke_symmetric_cipher_suite cs{tmp};
            cs.write_json(a);
        }
        a.close();
        wrapper.close();
    }

};

// Following draft-ietf-tls-esni-18:
//
// The following ECH configuration extension values are RESERVED for
// use by servers to "grease" clients, as inspired by RFC8701. Servers
// SHOULD randomly select from reserved values with the high-order bit
// clear, and clients MUST will ignore those extensions.
//
//    0x0000, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A,
//    0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA
//
// The draft says that the data format is:
//
//     struct {
//        ECHConfigExtensionType type;
//        opaque data<0..2^16-1>;
//     } ECHConfigExtension;
//
//  ... but in practice the data appears to be optional.
//
class ech_config_extension {
    encoded<uint16_t> type;     // type code
    datum data;                 // optional data

public:

    ech_config_extension(datum &d) :
        type{d},
        data{d}
    { }

    bool is_valid() const { return data.is_not_null(); }

    void write_json(json_array &a) const {
        if (!is_valid()) { return; }
        json_object o{a};
        if (is_grease()) {
            o.print_key_string("type", "GREASE");
        } else {
            o.print_key_string("type", "UNKNOWN");
            o.print_key_uint("type_code", type.value());
        }
        if (data.is_not_null()) {
            o.print_key_hex("data", data);
        }
        o.close();
    }

    bool is_grease() const {
        return type.value() == 0 || ((type.value() & 0x0a0a) == 0x0a0a);
    }

};


// Following draft-ietf-tls-esni-18:
//
//   struct {
//       HpkeKeyConfig key_config;
//       uint8 maximum_name_length;
//       opaque public_name<1..255>;
//       Extension extensions<0..2^16-1>;
//   } ECHConfigContents;
//
class ech_config_contents_version_f30d {
    hpke_key_config key_config;
    encoded<uint8_t> maximum_name_length;
    opaque<uint8_t> public_name;
    datum extension_list;

public:

    ech_config_contents_version_f30d(datum &d) :
        key_config{d},
        maximum_name_length{d},
        public_name{d},
        extension_list{d}
    { }

    void write_json(json_object &o) const {
        key_config.write_json(o);
        o.print_key_uint8("maximum_name_length", maximum_name_length.value());
        o.print_key_json_string("public_name", public_name.get_value());

        json_array a{o, "extensions"};
        for (ech_config_extension &extn : sequence<ech_config_extension>{extension_list}) {
            extn.write_json(a);
        }
        a.close();
    }

};


// Following draft-ietf-tls-esni-18:
//
//   struct {
//       uint16 version;
//       uint16 length;
//       select (ECHConfig.version) {
//         case 0xfe0d: ECHConfigContents contents;
//       }
//   } ECHConfig;
//

class ech_config {
    encoded<uint16_t> redundant_length;
    encoded<uint16_t> version;
    encoded<uint16_t> length;
    ech_config_contents_version_f30d contents;

public:

    ech_config(datum &d) :
        redundant_length{d},
        version{d},
        length{d},
        contents{d}
    { }

    void write_json(json_object &o) const {
        json_object ech_config_json{o, "ech_config"};
        ech_config_json.print_key_uint16_hex("version", version.value());
        contents.write_json(ech_config_json);
        ech_config_json.close();
    }

    // ech_config::get_json_string() is used by the cython library
    //
    std::string get_json_string(size_t buf_size) {
        // create string_buffer_stream
        //
        json_string buf{buf_size};

        // attempt to write a json_object into the buffer
        //
        json_object ech_config_json{buf};
        this->write_json(ech_config_json);
        ech_config_json.close();

        // get json string representation
        //
        std::string json_str = buf.get_string();

        return json_str;
    }
};


// ECHClientHello, following Section 5 of
// https://datatracker.ietf.org/doc/draft-ietf-tls-esni/18/
//
//   enum {
//        encrypted_client_hello(0xfe0d), (65535)
//     } ExtensionType;
//
// The payload of the extension has the following structure:
//
//     enum { outer(0), inner(1) } ECHClientHelloType;
//
//     struct {
//        ECHClientHelloType type;
//        select (ECHClientHello.type) {
//            case outer:
//                HpkeSymmetricCipherSuite cipher_suite;
//                uint8 config_id;
//                opaque enc<0..2^16-1>;
//                opaque payload<1..2^16-1>;
//            case inner:
//                Empty;
//        };
//     } ECHClientHello;
//
class ech_client_hello {
    encoded<uint8_t> ech_client_hello_type;
    hpke_symmetric_cipher_suite cs;
    encoded<uint8_t> config_id;
    opaque<uint16_t> enc;
    opaque<uint16_t> payload;

public:

    ech_client_hello(datum &d) :
        ech_client_hello_type{d},
        cs{d},
        config_id{d},
        enc{d},
        payload{d}
    { }

    void write_json(json_object &o) const {
        json_object ech_client_hello_json{o, "ech_client_hello"};
        cs.write_json(ech_client_hello_json);
        ech_client_hello_json.print_key_uint("config_id", config_id.value());
        if constexpr (false) {
            //
            // this data is too verbose for large-scale observations
            //
            enc.write_json(ech_client_hello_json, "enc");
            payload.write_json(ech_client_hello_json, "payload");
        } else {
            ech_client_hello_json.print_key_uint("payload_length", (size_t)payload.get_length());
        }
        ech_client_hello_json.close();
    }

};

#endif // ECH_HPP
