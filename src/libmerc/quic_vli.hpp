// quic_vli.hpp
//
// variable-length integers as used by the QUIC protocol

#ifndef QUIC_VLI_HPP
#define QUIC_VLI_HPP

// class variable_length_integer implements the QUIC variable-length
// integer encoding (following RFC9000, Section 16).  If there is a
// parse error, i.e. the datum being parsed is too short, then the datum
// reference passed to the constructor will be set to NULL state.  The
// value of the variable length integer is returned by the member function
// value().
//
//          +======+========+=============+=======================+
//          | 2MSB | Length | Usable Bits | Range                 |
//          +======+========+=============+=======================+
//          | 00   | 1      | 6           | 0-63                  |
//          +------+--------+-------------+-----------------------+
//          | 01   | 2      | 14          | 0-16383               |
//          +------+--------+-------------+-----------------------+
//          | 10   | 4      | 30          | 0-1073741823          |
//          +------+--------+-------------+-----------------------+
//          | 11   | 8      | 62          | 0-4611686018427387903 |
//          +------+--------+-------------+-----------------------+
//
class variable_length_integer {
    uint64_t value_;

public:
    variable_length_integer(const variable_length_integer &i) : value_{i.value()} {   }

    variable_length_integer(uint64_t i) : value_{i} {   }

    variable_length_integer(datum &d) : value_{0} {
        uint8_t b;
        d.read_uint8(&b);
        int len=0;
        switch (b & 0xc0) {
        case 0xc0:
            len = 8;
            break;
        case 0x80:
            len = 4;
            break;
        case 0x40:
            len = 2;
            break;
        case 0x00:
            len = 1;
        }
        value_ = (b & 0x3f);
        for (int i=1; i<len; i++) {
            value_ *= 256;
            d.read_uint8(&b);
            value_ += b;
        }
    }

    void operator =(const variable_length_integer &i){
        value_ = i.value();
    }

    uint64_t value() const { return value_; }

};

class variable_length_integer_datum : public datum {

public:

    variable_length_integer_datum(datum &d) {
        uint8_t b;
        d.lookahead_uint8(&b);
        int len=0;
        switch (b & 0xc0) {
        case 0xc0:
            len = 8;
            break;
        case 0x80:
            len = 4;
            break;
        case 0x40:
            len = 2;
            break;
        case 0x00:
            len = 1;
        }
        datum::parse(d, len);
    }

    void write(buffer_stream &b) const {
        b.raw_as_hex(data, length());
    }

    bool is_grease() const {
        datum tmp = *this;               // copy to avoid changing *this
        variable_length_integer v{tmp};
        return v.value() % 31 == 27;
    }

    uint64_t value() const {
        datum tmp = *this;               // copy to avoid changing *this
        variable_length_integer v{tmp};
        return v.value();
    }
};

#endif // QUIC_VLI_HPP
