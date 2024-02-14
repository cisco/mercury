// ech.hpp
//
// encrypted client hello

#ifndef ECH_HPP
#define ECH_HPP

#include "datum.h"
#include "hpke_params.h"


//
// experimental data structures
//


// sequence<T> parses a sequence of type T from a datum
//
template <typename T>
class sequence_old {
    datum tmp;
    T value;

public:

    sequence_old(const datum &d) : tmp{d}, value{tmp} { }

    T* next() {
        if (tmp.is_not_empty()) {
            T *tmp_ptr = &value;
            value = T{tmp};
            return tmp_ptr;
        }
        return nullptr;
    }

    T* begin() {
        tmp.fprint(stderr); fputc('\n', stderr);
        return &value;
    }

    T* end() { return nullptr; }

    // T* operator++ () {
    //     fprintf(stderr, "incrementing\n");
    //     tmp.fprint(stderr); fputc('\n', stderr);
    //     value = T{tmp};
    //     if (tmp.is_not_empty()) {
    //         return &value;
    //     }
    //     return nullptr;
    // }

};


// template <typename T>
// class vector<T> {
//     encoded<T> length;
// };

// TLS opaque data
//
template <typename T>
class opaque {
    encoded<T> length;
    datum elements;

public:

    opaque(datum &d) : length{d}, elements{d, length} { }

    void write_json(json_object &o, const char *name) const {
        o.print_key_hex(name, elements);
        // json_object wrapper{o, name};
        // wrapper.print_key_uint("length", length);
        // wrapper.print_key_hex("", elements);
        // wrapper.close();
    }

    datum get_value() const { return elements; }
};



// From draft-ietf-tls-esni-17:
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

    void write_json(json_array &a) const {
        json_object wrapper{a};
        kdf_id.write_json(wrapper);
        aead_id.write_json(wrapper);
        wrapper.close();
    }
};

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
    //datum hpke_symmetric_cipher_suite;

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
        //wrapper.print_key_hex("hpke_symmetric_cipher_suites", hpke_symmetric_cipher_suite);
        wrapper.close();
    }

};

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
    // extension

public:

    ech_config_contents_version_f30d(datum &d) :
        key_config{d},
        maximum_name_length{d},
        public_name{d}
    { }

    void write_json(json_object &o) const {
        key_config.write_json(o);
        o.print_key_uint8("maximum_name_length", maximum_name_length.value());
        o.print_key_json_string("public_name", public_name.get_value());
        //public_name.write_json(o, "public_name");
    }
};



//   struct {
//       uint16 version;
//       uint16 length;
//       select (ECHConfig.version) {
//         case 0xfe0d: ECHConfigContents contents;
//       }
//   } ECHConfig;
//
class ech_config {
    encoded<uint16_t> dummy;
    encoded<uint16_t> version;
    encoded<uint16_t> length;   // note: order of length and version fields differ from draft
    ech_config_contents_version_f30d contents;

public:

    ech_config(datum &d) :
        dummy{d},         // ???
        version{d},
        length{d},
        contents{d}
    { }

    void write_json(json_object &o) const {
        // o.print_key_uint16("dummy", dummy.value());
        o.print_key_uint16("length", length.value());
        o.print_key_uint16_hex("version", version.value());
        contents.write_json(o);
    }

};


#endif // ECH_HPP
