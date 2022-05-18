// pcap.h
//
// C++ header-only implementation of the PCAP-NG (Packet Capture Next
// Generation) file format

// TODO:
//
//   0.  Add defensive coding where needed
//
//   1.  Implement traditional PCAP file format reader [DONE]
//
//   2.  Implement traditional PCAP file writer
//
//   3.  Implement a basic PCAP-NG file writer
//
//   4.  Unify implementations into a single class that determines the
//       format of a file from its initial bytes [DONE]


#ifndef PCAP_H
#define PCAP_H

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>

#include <variant>

#include "libmerc/datum.h"

// class errno_exception is a thread-safe standard exception
// runtime_error that holds the a C-library error message associated
// with the errno variable.  It should be thrown immediately after the
// function that caused the error.
//
// Implementation notes: strerror() is not thread-safe, and
// strerror_r() is thread-safe but has portability issues across
// POSIX/GNU.  In contrast, strerror_l() is thread-safe and has no
// portability issues.
//
class errno_exception : public std::runtime_error {
public:
    errno_exception() : runtime_error{strerror_l(errno, (locale_t)0)} { };
    //  errno_exception() : runtime_error{strerror_l(errno, uselocale((locale_t)0))} { };
};

// class file_datum represents a read-only file on disk; it inherits
// the interface of class datum, and thus can be used to read and
// parse files
//
class file_datum : public datum {
    int fd = -1;
    uint8_t *addr;
    size_t file_length;

public:

    file_datum(const char *fname) : fd{open(fname, O_RDONLY)} {

        if (fd < 0) {
            throw errno_exception();
        }
        struct stat statbuf;
        if (fstat(fd, &statbuf) != 0) {
            throw errno_exception();
        }
        file_length = statbuf.st_size;
        fprintf(stderr, "opened file of length %zd bytes\n", file_length);

        data = (uint8_t *)mmap (0, file_length, PROT_READ, MAP_PRIVATE, fd, 0);
        if (data == MAP_FAILED) {
            data = data_end = nullptr;
            throw errno_exception();
        }
        data_end = data + file_length;
        addr = (uint8_t *)data;
    }

    // no copy constructor, because we own a file descriptor
    //
    file_datum(file_datum &rhs) = delete;

    ~file_datum() {
        fprintf(stderr, "closing file of length %zd bytes\n", file_length);
        if (munmap(addr, file_length) != 0) {
            ; // error, but don't throw errno_exception() because we are in a destructor
        }
        if (close(fd) != 0) {
            ; // error, but don't throw errno_exception() because we are in a destructor
        }
    }

};

// class ignore<T> parses a data element of type T, but then ignores
// (does not store) its value.  It can be used to check the format of
// data that need not be stored.
//
// TODO: the parameter T should be able to accept any class, not just
// unsigned integer types
//
template <typename T>
class ignore {

public:

    ignore(datum &d, bool little_endian=false) {
        (void)little_endian;
        size_t tmp;
        d.read_uint(&tmp, sizeof(T));
    }

    ignore() { }

    // TODO: write out static constexpr value for serialization
};

//
// PCAP
//

namespace pcap {

// PCAP File Header format
//                           1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    0 |                          Magic Number                         |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    4 |          Major Version        |         Minor Version         |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    8 |                           Reserved1                           |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   12 |                           Reserved2                           |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   16 |                            SnapLen                            |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   20 | FCS |f|                   LinkType                            |
//      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// The value of Magic Number is either 0xA1B2C3D4 or 0xA1B23C4D.  If
// it is 0xA1B2C3D4, time stamps in Packet Records are in seconds and
// microseconds; if it is 0xA1B23C4D, time stamps in Packet Records
// are in seconds and nanoseconds.
//
// Major Version = 2, Minor Version = 4
//
class pcap_file_header {

    class magic_values : public encoded<uint32_t> {
    public:
        magic_values(datum &d) : encoded<uint32_t>{d} {
            if (this->value() == magic_nsec) {
                char errmsg_buf[34] = "unsupported file magic: ";
                sprintf(errmsg_buf + 25, "%08x", this->value());
                throw std::runtime_error(errmsg_buf);
            }
            if (this->value() != magic && this->value() != magic_nsec) {
                char errmsg_buf[34] = "unrecognized file magic: ";
                sprintf(errmsg_buf + 25, "%08x", this->value());
                throw std::runtime_error(errmsg_buf);
            }
        }
        magic_values(uint32_t v) : encoded<uint32_t>{v} {}
    };

    magic_values magic_number;
    encoded<uint16_t> major_version;
    encoded<uint16_t> minor_version;
    ignore<uint32_t> reserved1;
    ignore<uint32_t> reserved2;
    encoded<uint32_t> snaplen;
    encoded<uint32_t> linktype;   // TODO: deal with FCS thing

    static constexpr ssize_t size = sizeof(uint32_t) * 7; // number of bytes in header

public:

    static constexpr uint32_t magic      = 0xd4c3b2a1;  // sec/usec
    static constexpr uint32_t magic_nsec = 0x4d3cb2a1;  // sec/nsec

    pcap_file_header(datum &d) :
        magic_number{d},
        major_version{d, magic_number == magic},
        minor_version{d, magic_number == magic},
        reserved1{d, magic_number == magic},
        reserved2{d, magic_number == magic},
        snaplen{d, magic_number == magic},
        linktype{d, magic_number == magic}
    { }

    // constructor for writing file_header
    //
    pcap_file_header(uint32_t snap, uint16_t lt) :
        magic_number{magic},
        major_version{2},
        minor_version{4},
        //reserved1{0},
        //reserved2{0},
        snaplen{snap},
        linktype{lt}
    { }

    ssize_t write(datum &buf) {
        if (buf.length() < size) {
            return -1; // error: not enough room in buf
        }
        // memcpy / std::copy()
    }

    void fprint(FILE *f) {
        fprintf(f, "magic_number: %x\n", magic_number.value());
        fprintf(f, "major_version: %u\n", major_version.value());
        fprintf(f, "minor_version: %u\n", minor_version.value());
        fprintf(f, "snaplen: %u\n", snaplen.value());
        fprintf(f, "linktype: %u\n", linktype.value());
    }

    uint32_t get_linktype() const { return linktype; }

    bool byteswap() const { return magic_number == magic; }
};

// Packet Record format
//
//                    1                   2                   3
//       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     0 |                      Timestamp (Seconds)                      |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     4 |            Timestamp (Microseconds or nanoseconds)            |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//     8 |                    Captured Packet Length                     |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    12 |                    Original Packet Length                     |
//       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    16 /                                                               /
//       /                          Packet Data                          /
//       /                        variable length                        /
//       /                                                               /
//       +---------------------------------------------------------------+
//
class pcap_packet_record {
    encoded<uint32_t> timestamp_sec;
    encoded<uint32_t> timestamp_usec;
    encoded<uint32_t> caplen;
    encoded<uint32_t> len;
    datum packet_data;

public:

    pcap_packet_record(datum &d, bool swap_byte_order) :
        timestamp_sec{d, swap_byte_order},
        timestamp_usec{d, swap_byte_order},
        caplen{d, swap_byte_order},
        len{d, swap_byte_order},
        packet_data{d, caplen}
    {  }

    void fprint(FILE *f) {
        fprintf(f, "timestamp_sec:  %u\n", timestamp_sec.value());
        fprintf(f, "timestamp_usec: %u\n", timestamp_usec.value());
        fprintf(f, "caplen: %u\n", caplen.value());
        fprintf(f, "len: %u\n", len.value());
        fprintf(f, "data: ");
        packet_data.fprint(f);
        fprintf(f, "\n");
    }

    datum get_packet() const { return packet_data; }
};

//
// PCAP-NG (Next Generation)
//

// pad_len(length) returns the number that, when added to length,
// rounds that value up to the next multiple of four
//
static inline size_t pad_len(size_t length) {
    switch (length % 4) {
    case 3: return 1;
    case 2: return 2;
    case 1: return 3;
    case 0:
    default:
        ;
    }
    return 0;
}

// class block_header represents the header fields that are common to
// all block fomats
//
class block_header {
    encoded<uint32_t> block_type;
    encoded<uint32_t> block_total_length;

public:

    block_header(datum &d, bool byteswap_needed=false) :
        block_type{d, byteswap_needed},
        block_total_length{d, byteswap_needed}
    {
        // if (byteswap_needed) {
        //     swap_byte_order();
        // }
    }
    // block_header(datum &d, bool byteswap_needed=false) :
    //     block_type{accept<uint32_t>(d)},
    //     block_total_length{accept<uint32_t>(d)}
    // {
    //     if (byteswap_needed) {
    //         swap_byte_order();
    //     }
    // }

    // block_header(datum &d, bool byteswap_needed=false) {
    //     d.read_uint32(&block_type);
    //     d.read_uint32(&block_total_length);
    //
    //     if (byteswap_needed) {
    //         swap_byte_order();
    //     }
    // }

    static constexpr size_t length = 8;  // # bytes in block header

    // swap_byte_order() is needed to process a section header block,
    // in which the byte order is not indicated until the 'magic'
    // field has been read from the body of the block
    //
    void swap_byte_order() {
        block_type.swap_byte_order();
        block_total_length.swap_byte_order();
    }

    uint32_t type() const { return block_type; }

    uint32_t block_length() const { return block_total_length; }
};

class block_footer {
    datum options;

public:

    block_footer(datum &d, size_t options_length, bool byteswap_needed) {

        options.parse(d, options_length);
        uint32_t block_total_length;
        d.read_uint32(&block_total_length);
        if (byteswap_needed) {
            block_total_length = ntohl(block_total_length);
        }
    }
};

// Option format
//
//                      1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      Option Code              |         Option Length         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                       Option Value                            /
// /              variable length, padded to 32 bits               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// /                                                               /
// /                 . . . other options . . .                     /
// /                                                               /
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   Option Code == opt_endofopt |   Option Length == 0          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//

class option {
    uint16_t code;
    uint16_t length;
    datum value;

public:

    option(datum &d, bool byteswap) {
        fprintf(stderr, "%s\n", __func__);
        d.read_uint16(&code);
        d.read_uint16(&length);
        if (byteswap) {
            code = htons(code);
            length = htons(length);
        }
        value.parse(d, length);
        d.skip(pad_len(length));

        fprintf(stderr, "code:   %u\n", code);
        fprintf(stderr, "length: %u\n", length);
        // value.fprint(stderr); fputc('\n', stderr);
    }

    enum type {
        endofopt = 0,
        comment  = 1,

        // isb_type option types are only used in Interface Statistics
        // Block options
        //
        isb_starttime 	 = 2,
        isb_endtime 	 = 3,
        isb_ifrecv 	     = 4,
        isb_ifdrop 	     = 5,
        isb_filteraccept = 6,
        isb_osdrop 	     = 7,
        isb_usrdeliv 	 = 8,

        // custom types
        //
        custom_utf8 = 2988,
        custom_octets = 2989,
        custom_utf8_noncopyable = 19372,
        custom_octets_noncopyable = 19373,

    };


    uint16_t get_type() const { return code; }

    datum get_value() const { return value; }
};

//    TODO: options processing requires computing the length of the
//    options field by subtracting some values from the block total
//    length.  If the data is ill-formed, that value could be wrong,
//    and if the computation uses a size_t, it could be close to
//    UINT_MAX.  A ssize_t should be used instead, and there should be
//    a > 0 check in the right places, so that the problem is caught
//    right where it occurs.


// Section Header Block format
//
//                         1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  0 |                   Block Type = 0x0A0D0D0A                     |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  4 |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  8 |                      Byte-Order Magic                         |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 12 |          Major Version        |         Minor Version         |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 16 |                                                               |
//    |                          Section Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 24 /                                                               /
//    /                      Options (variable)                       /
//    /                                                               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
class section_header_block {
    uint32_t block_type;
    uint32_t block_total_length;
    uint32_t magic;
    uint16_t major_version;
    uint16_t minor_version;
    uint64_t section_length;
    datum options;
    bool byteswap_needed = false;

    static constexpr size_t non_option_length = 28;

public:

    static constexpr uint32_t type = 0x0a0d0d0a;

    section_header_block(datum &d) {
        fprintf(stderr, "%s\n", __func__);
        d.read_uint32(&block_type);
        d.read_uint32(&block_total_length);
        d.read_uint32(&magic);
        d.read_uint16(&major_version);
        d.read_uint16(&minor_version);
        d.read_uint(&section_length, 8);

        if (d.is_not_readable()) {
            return;
        }

        switch (magic) {
        case 0x1a2b3c4d:
            byteswap_needed = false;
            break;
        case 0x4d3c2b1a:
            byteswap_needed = true;
            break;
        default:
            throw std::runtime_error("invalid byte order magic string");   // error
        }

        if (byteswap_needed) {
            block_total_length = ntohl(block_total_length);
            major_version = ntohs(major_version);
            minor_version = ntohs(minor_version);
            section_length = htobe64(section_length);
        }

        ssize_t options_length = block_total_length - non_option_length;
        options.parse(d, options_length);

        uint32_t tmp;
        d.read_uint32(&tmp); // second block_length; ignore for now

        fprintf(stderr, "byteswap_needed:    %u\n", byteswap_needed);
        fprintf(stderr, "block_type:         %x\n", block_type);
        fprintf(stderr, "block_total_length: %u\n", block_total_length);
        fprintf(stderr, "magic:              %x\n", magic);
        fprintf(stderr, "major_version:      %u\n", major_version);
        fprintf(stderr, "minor_version:      %u\n", minor_version);
        fprintf(stderr, "section_length:     %lx\n", section_length);
        fprintf(stderr, "options_length:     %lx\n", options_length);
        options.fprint_hex(stderr); fputc('\n', stderr);

        while (options.is_not_empty()) {
            option opt{options, byteswap_needed};
            //            opt.fprint(stderr);
        }

        fprintf(stderr, "data length: %zu\n", d.length());
        d.fprint_hex(stderr); fputc('\n', stderr);
    }

    bool byteswap() const { return byteswap_needed; }

};

// Interface Description Block format
//
//                         1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  0 |                    Block Type = 0x00000001                    |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  4 |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  8 |           LinkType            |           Reserved            |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 12 |                            SnapLen                            |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 16 /                                                               /
//    /                      Options (variable)                       /
//    /                                                               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//

class interface_description_block {
    uint16_t linktype;
    uint16_t reserved;
    uint32_t snaplen;
    datum options;

    static constexpr size_t non_option_length = 20;

public:

    interface_description_block(datum &d, ssize_t block_total_length, bool byteswap_needed) {
        fprintf(stderr, "%s\n", __func__);
        d.read_uint16(&linktype);
        d.read_uint16(&reserved);
        d.read_uint32(&snaplen);

        if (d.is_null()) {
            return;
        }

        if (byteswap_needed) {
            linktype = ntohs(linktype);
            snaplen = ntohl(snaplen);
        }

        ssize_t options_length = block_total_length - non_option_length;
        options.parse(d, options_length);

        uint32_t tmp;
        d.read_uint32(&tmp); // second block_length; ignore for now

        fprintf(stderr, "byteswap_needed:    %u\n", byteswap_needed);
        fprintf(stderr, "linktype:           %u\n", linktype);
        fprintf(stderr, "reserved:           %u\n", reserved);
        fprintf(stderr, "snaplen:            %u\n", snaplen);
        fprintf(stderr, "options_length:     %lx\n", options_length);
        options.fprint_hex(stderr); fputc('\n', stderr);

        while (options.is_not_empty()) {
            option opt{options, byteswap_needed};
            //            opt.fprint(stderr);
        }

        fprintf(stderr, "data length: %zu\n", d.length());
        d.fprint_hex(stderr); fputc('\n', stderr);

    }

    uint16_t get_linktype() const { return linktype; }

};


//  Name Resolution Block format
//
//  The Name Resolution Block (NRB) holds IPv4 and/or IPv6 addresses
//  and the corresponding canonical names at the time of capture; it
//  is optional.
//
//                         1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  0 |                    Block Type = 0x00000004                    |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  4 |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  8 |      Record Type              |      Record Value Length      |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 12 /                       Record Value                            /
//    /              variable length, padded to 32 bits               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    .                                                               .
//    .                  . . . other records . . .                    .
//    .                                                               .
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |  Record Type = nrb_record_end |   Record Value Length = 0     |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    /                                                               /
//    /                      Options (variable)                       /
//    /                                                               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// nrb_record_ipv4:
//
//    The nrb_record_ipv4 record specifies an IPv4 address (contained
//    in the first 4 octets), followed by one or more zero-terminated
//    UTF-8 strings containing the DNS entries for that address. The
//    minimum valid Record Length for this Record Type is thus 6: 4
//    for the IP octets, 1 character, and a zero-value octet
//    terminator. Note that the IP address is treated as four octets,
//    one for each octet of the IP address; it is not a 32-bit word,
//    and thus the endianness of the SHB does not affect this field's
//    value.
//
class nrb_record_ipv4 {
    uint32_t addr;
    datum strings;

public:

    nrb_record_ipv4(datum &d) {
        d.read_uint32(&addr);
        strings = d;
    }

    void fprint(FILE *f) const {
        uint8_t *a = (uint8_t *)&addr;
        fprintf(f, "%u.%u.%u.%u\t", a[0], a[1], a[2], a[3]);
        strings.fprint(f); fputc('\n', f);
    }

};

class nrb_record_ipv6 {
    std::array<uint8_t,16> a{ 0, };
    datum strings;

public:

    nrb_record_ipv6(datum &d) {
        d.read_array(a);
        strings = d;
    }

    void fprint(FILE *f) const {
        //
        // TODO: implement compressed output
        //
        fprintf(f, "%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u:%u\t",
                a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
                a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]);
        strings.fprint(f); fputc('\n', f);
    }

};


class name_resolution_record {
    uint16_t record_type;
    uint16_t record_value_length;
    datum value;

public:

    name_resolution_record(datum &d, bool byteswap_needed) {
        fprintf(stderr, "%s\n", __func__);
        d.read_uint16(&record_type);
        d.read_uint16(&record_value_length);
        if (byteswap_needed) {
            record_type = ntohs(record_type);
            record_value_length = ntohs(record_value_length);
        }
        value.parse(d, record_value_length);
        d.skip(pad_len(record_value_length));
    }

    enum type : uint16_t {
        end  = 0,
        ipv4 = 1,
        ipv6 = 2,
    };

    uint16_t get_type() const { return record_type; }

    const datum get_value() const { return value; }

    size_t length() const { return 4 + record_value_length + pad_len(record_value_length); }

};

class name_resolution_block {
    datum records;
    // note: footer is in constructor

    // fixed_fields_length holds the sum of the lengths of the
    // Block Type and both Block Total Length fields
    //
    static constexpr size_t fixed_fields_length = 12;

public:

    name_resolution_block(datum &d, size_t block_length, bool byteswap_needed) {
        fprintf(stderr, "%s\n", __func__);
        records = d;

        size_t records_length = 0;
        while (d.is_not_empty()) {
            name_resolution_record nrr{d, byteswap_needed};
            records_length += nrr.length();
            if (nrr.get_type() == name_resolution_record::type::end) {
                break;
            }
            if (nrr.get_type() == name_resolution_record::type::ipv4) {
                datum value = nrr.get_value();
                nrb_record_ipv4 ipv4{value};
                ipv4.fprint(stderr); fputc('\n', stderr);
            }
            if (nrr.get_type() == name_resolution_record::type::ipv6) {
                datum value = nrr.get_value();
                nrb_record_ipv6 ipv6{value};
                ipv6.fprint(stderr); fputc('\n', stderr);
            }
        }

        size_t options_length = block_length - records_length - fixed_fields_length;
        fprintf(stderr, "options_length: %zu\n", options_length);
        d.fprint_hex(stderr); fputc('\n', stderr);
        block_footer footer{d, options_length, byteswap_needed};
    }

};

// Enhanced Packet Block format
//
//                      1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  0 |                    Block Type = 0x00000006                    |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  4 |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  8 |                         Interface ID                          |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 12 |                        Timestamp (High)                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 16 |                        Timestamp (Low)                        |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 20 |                    Captured Packet Length                     |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 24 |                    Original Packet Length                     |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 28 /                                                               /
//    /                          Packet Data                          /
//    /              variable length, padded to 32 bits               /
//    /                                                               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    /                                                               /
//    /                      Options (variable)                       /
//    /                                                               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

class enhanced_packet_block {
    //    block_header header;

    uint32_t interface_id;
    uint32_t timestamp_hi;
    uint32_t timestamp_lo;
    uint32_t caplen;
    uint32_t len;
    datum packet;

    // fixed_length holds the number of non-option bytes in block
    // header, except for the packet field and associated padding
    // needed to round its length up to a multiple of four
    //
    static constexpr size_t fixed_length = 32;

    enum epb_option {
        epb_flags 	= 2,
        epb_hash 	= 3,
        epb_dropcount = 4,
        epb_packetid  = 5,
        epb_queue 	= 6,
        epb_verdict = 7,
    };

public:

    enhanced_packet_block(datum &d, size_t block_length, bool byteswap_needed) { //: header{d, byteswap_needed} {
        fprintf(stderr, "%s\n", __func__);
        d.read_uint32(&interface_id);
        d.read_uint32(&timestamp_hi);
        d.read_uint32(&timestamp_lo);
        d.read_uint32(&caplen);
        d.read_uint32(&len);

        if (byteswap_needed) {
            interface_id = ntohl(interface_id);
            timestamp_hi = ntohl(timestamp_hi);
            timestamp_lo = ntohl(timestamp_lo);
            caplen       = ntohl(caplen);
            len          = ntohl(len);
        }

        packet.parse(d, caplen);
        d.skip(pad_len(caplen));

        fprintf(stderr, "interface_id: %u\n", interface_id);
        fprintf(stderr, "timestamp_hi: %u\n", timestamp_hi);
        fprintf(stderr, "timestamp_lo: %u\n", timestamp_lo);
        fprintf(stderr, "caplen: %u\n", caplen);
        fprintf(stderr, "len: %u\n", len);
        packet.fprint_hex(stderr); fputc('\n', stderr);

        ssize_t options_length = block_length - fixed_length - (caplen + pad_len(caplen));
        block_footer footer{d, options_length, byteswap_needed};

    }

    datum get_packet() const {
        return packet;
    }

};

// Simple Packet Block format
//
//                         1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  0 |                    Block Type = 0x00000003                    |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  4 |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  8 |                    Original Packet Length                     |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 12 /                                                               /
//    /                          Packet Data                          /
//    /              variable length, padded to 32 bits               /
//    /                                                               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//
class simple_packet_block {
    uint32_t original_packet_length;
    datum packet;

    // Original Packet Length (32 bits): an unsigned value indicating
    // the actual length of the packet when it was transmitted on the
    // network. It can be different from length of the Packet Data
    // field's length if the packet has been truncated by the capture
    // process, in which case the SnapLen value in Section 4.2 will be
    // less than this Original Packet Length value, and the SnapLen
    // value MUST be used to determine the size of the Packet Data
    // field length.

    // Packet Data: the data coming from the network, including
    // link-layer headers. The length of this field can be derived
    // from the field Block Total Length, present in the Block Header,
    // and it is the minimum value among the SnapLen (present in the
    // Interface Description Block) and the Original Packet Length
    // (present in this header). The format of the data within this
    // Packet Data field depends on the LinkType field specified in
    // the Interface Description Block (see Section 4.2) and it is
    // specified in the entry for that format in [LINKTYPES].

    // fixed_length holds the number of non-option bytes in block
    // header, except for the packet field and associated padding
    // needed to round its length up to a multiple of four
    //
    static constexpr size_t fixed_length = 16;

public:

    simple_packet_block(datum &d, size_t block_length, bool byteswap_needed) { //: header{d, byteswap_needed} {
        fprintf(stderr, "%s\n", __func__);
        d.read_uint32(&original_packet_length);
        if (byteswap_needed) {
            original_packet_length = ntohl(original_packet_length);
        }

        ssize_t caplen = block_length - fixed_length;
        packet.parse(d, caplen);
        d.skip(pad_len(caplen));

        fprintf(stderr, "caplen: %zd\n", caplen);
        fprintf(stderr, "original_packet_length: %u\n", original_packet_length);
        packet.fprint_hex(stderr); fputc('\n', stderr);

        // TODO: add block total length field
    }

    datum get_packet() const {
        return packet;
    }

};



// The following options are used in Interface Statistics Blocks.  All
// the fields that refer to packet counters are 64-bit values,
// represented with the octet order of the current section.

// The isb_starttime option specifies the time the capture started;
// time will be stored in two blocks of four octets each. The format
// of the timestamp is the same as the one defined in the Enhanced
// Packet Block (Section 4.3); the length of a unit of time is
// specified by the 'if_tsresol' option (see Figure 10) of the
// Interface Description Block referenced by this packet.

class isb_starttime {
    uint32_t timestamp_hi;
    uint32_t timestamp_lo;

public:

    isb_starttime(datum &d, bool byteswap) {
        fprintf(stderr, "%s\n", __func__);
        d.read_uint32(&timestamp_hi);
        d.read_uint32(&timestamp_lo);

        if (byteswap) {
            timestamp_hi = ntohl(timestamp_hi);
            timestamp_lo = ntohl(timestamp_lo);
        }
    }

    void fprint(FILE *f) const {
        fprintf(f, "timestamp_hi: %u\n", timestamp_hi);
        fprintf(f, "timestamp_lo: %u\n", timestamp_lo);
    }
};

// The isb_endtime option specifies the time the capture ended; time
// will be stored in two blocks of four octets each. The format of the
// timestamp is the same as the one defined in the Enhanced Packet
// Block (Section 4.3); the length of a unit of time is specified by
// the 'if_tsresol' option (see Figure 10) of the Interface
// Description Block referenced by this packet.

class isb_endtime {
    uint32_t timestamp_hi;
    uint32_t timestamp_lo;

public:

    isb_endtime(datum &d, bool byteswap) {
        fprintf(stderr, "%s\n", __func__);
        d.read_uint32(&timestamp_hi);
        d.read_uint32(&timestamp_lo);

        if (byteswap) {
            timestamp_hi = ntohl(timestamp_hi);
            timestamp_lo = ntohl(timestamp_lo);
        }
    }

    void fprint(FILE *f) const {
        fprintf(f, "timestamp_hi: %u\n", timestamp_hi);
        fprintf(f, "timestamp_lo: %u\n", timestamp_lo);
    }
};


//    The isb_ifrecv option specifies the 64-bit unsigned integer
//    number of packets received from the physical interface starting
//    from the beginning of the capture.
//
class isb_ifrecv {
    uint64_t count;

public:

    isb_ifrecv(datum &d, bool byteswap) {
        fprintf(stderr, "%s\n", __func__);
        d.read_uint(&count, 8);

        if (byteswap) {
            count = htobe64(count);
        }
    }

    void fprint(FILE *f) const {
        fprintf(f, "count: %lu\n", count);
    }
};

//    The isb_ifdrop option specifies the 64-bit unsigned integer
//    number of packets dropped by the interface due to lack of
//    resources starting from the beginning of the capture.
//
class isb_ifdrop {
    uint64_t count;

public:

    isb_ifdrop(datum &d, bool byteswap) {
        fprintf(stderr, "%s\n", __func__);
        d.read_uint(&count, 8);

        if (byteswap) {
            count = htobe64(count);
        }
    }

    void fprint(FILE *f) const {
        fprintf(f, "count: %lu\n", count);
    }
};

//    The isb_filteraccept option specifies the 64-bit unsigned
//    integer number of packets accepted by filter starting from the
//    beginning of the capture.

//    The isb_osdrop option specifies the 64-bit unsigned integer
//    number of packets dropped by the operating system starting from
//    the beginning of the capture.

//    The isb_usrdeliv option specifies the 64-bit unsigned integer
//    number of packets delivered to the user starting from the
//    beginning of the capture. The value contained in this field can
//    be different from the value 'isb_filteraccept - isb_osdrop'
//    because some packets could still be in the OS buffers when the
//    capture ended.

// Interface Statistics Block format
//
//                         1                   2                   3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  0 |                   Block Type = 0x00000005                     |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  4 |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  8 |                         Interface ID                          |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 12 |                        Timestamp (High)                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 16 |                        Timestamp (Low)                        |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 20 /                                                               /
//    /                      Options (variable)                       /
//    /                                                               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |                      Block Total Length                       |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
//

class interface_statistics_block {
    uint32_t interface_id;
    uint32_t timestamp_hi;
    uint32_t timestamp_lo;
    datum options;
    bool swap_byte_order;

    // fixed_length is the sum of the lengths of all of the fixed fields
    // (that is, all fields except the options)
    //
    static constexpr size_t fixed_length = 24;

public:

    interface_statistics_block(datum &d, size_t block_length, bool byteswap) {
        fprintf(stderr, "%s\n", __func__);
        d.read_uint32(&interface_id);
        d.read_uint32(&timestamp_hi);
        d.read_uint32(&timestamp_lo);

        if (byteswap) {
            interface_id = ntohl(interface_id);
            timestamp_hi = ntohl(timestamp_hi);
            timestamp_lo = ntohl(timestamp_lo);
        }

        ssize_t options_length = block_length - fixed_length;
        options.parse(d, options_length);
        swap_byte_order = byteswap;
        d.skip(4);  // final block total length field
        //        block_footer footer{d, options_length, byteswap};
    }

    void fprint(FILE *f) const {
        fprintf(f, "interface_id: %u\n", interface_id);
        fprintf(f, "timestamp_hi: %u\n", timestamp_hi);
        fprintf(f, "timestamp_lo: %u\n", timestamp_lo);

        options.fprint(f); fputc('\n', f);
        options.fprint_hex(f); fputc('\n', f);
        datum tmp = options;
        while (tmp.is_not_empty()) {
            option opt{tmp, swap_byte_order};
            if (opt.get_type() == option::type::comment) {
                datum value = opt.get_value();
                value.fprint(f); fputc('\n', f);
            }
            if (opt.get_type() == option::type::isb_starttime) {
                datum value = opt.get_value();
                isb_starttime starttime{value, swap_byte_order};
                starttime.fprint(f);
                //value.fprint_hex(f); fputc('\n', f);
            }
            if (opt.get_type() == option::type::isb_endtime) {
                datum value = opt.get_value();
                isb_endtime endtime{value, swap_byte_order};
                endtime.fprint(f);
            }
            if (opt.get_type() == option::type::isb_ifrecv) {
                datum value = opt.get_value();
                isb_ifrecv ifrecv{value, swap_byte_order};
                ifrecv.fprint(f);
            }
            if (opt.get_type() == option::type::isb_ifdrop) {
                datum value = opt.get_value();
                isb_ifdrop ifdrop{value, swap_byte_order};
                ifdrop.fprint(f);
            }
            if (opt.get_type() == option::type::isb_filteraccept) {
                datum value = opt.get_value();
                value.fprint_hex(f); fputc('\n', f);
            }
            if (opt.get_type() == option::type::isb_osdrop) {
                datum value = opt.get_value();
                value.fprint_hex(f); fputc('\n', f);
            }
            if (opt.get_type() == option::type::isb_usrdeliv) {
                datum value = opt.get_value();
                value.fprint_hex(f); fputc('\n', f);
            }

            // note: we don't process option::type::end, because if
            // the options are well-formded then it wouldn't have any
            // effect, and if they are not well-formed, then there
            // might be interesting data after option of type::end.
        }
    }
};

// class pcap::file_reader reads packet capture files in either the
// PCAP (traditional Berkeley Packet Capture) format or PCAP-NG (PCAP
// Next Generation) format.  It is implemented as an abstract base
// class, whose derived classes are readers for those two formats.
//
class pcap_reader {

public:

    enum LINKTYPE : uint16_t {
        NULL_    =   0,  // BSD loopback encapsulation
        ETHERNET =   1,  // Ethernet
        PPP      =   9,  // Point-to-Point Protocol (PPP)
        RAW      = 101,  // Raw IP; begins with IPv4 or IPv6 header
        NONE     = 65535 // reserved, used here as 'none'
    };

    virtual const char *get_linktype() const = 0;

    virtual std::pair<const uint8_t *, const uint8_t *> read_packet() = 0;

};

// class pcap_ng represents a file in the PCAP-NG (Packet Capture Next
// Generation) format
//
class pcap_ng : public pcap_reader {
    uint16_t linktype = LINKTYPE::NONE; // default
    bool swap_byte_order;
    file_datum &file;

public:

    // pcap_ng(const char *fname) : file{fname} {
    //     section_header_block shb{file};
    //     swap_byte_order = shb.byteswap();
    //     //
    //     // TODO: advance up to packet block
    //     //
    // }

    pcap_ng(file_datum &f) : file{f} {
        section_header_block shb{file};
        swap_byte_order = shb.byteswap();
        fprintf(stderr, "file_datum: "); file.fprint_hex(stderr); fputc('\n', stderr);
        //
        // TODO: advance up to packet block
        //
    }

    enum LINKTYPE : uint16_t {
        NULL_    =   0,  // BSD loopback encapsulation
        ETHERNET =   1,  // Ethernet
        PPP      =   9,  // Point-to-Point Protocol (PPP)
        RAW      = 101,  // Raw IP; begins with IPv4 or IPv6 header
        NONE     = 65535 // reserved, used here as 'none'
    };

    const char *get_linktype() const {
        switch(linktype) {
        case LINKTYPE::NULL_:    return "NULL";
        case LINKTYPE::ETHERNET: return "ETHERNET";
        case LINKTYPE::PPP:      return "PPP";
        case LINKTYPE::RAW:      return "RAW";
        case LINKTYPE::NONE:     return "NONE";
        }
        return "unknown";
    }

    std::pair<const uint8_t *, const uint8_t *> read_packet() {

        while (file.is_not_empty()) {
            block_header block{file, swap_byte_order};
            fprintf(stderr, "got block with type %u and length %u\n", block.type(), block.block_length());
            if (block.block_length() == 0) {
                break;
            }
            if (block.type() == enhanced_packet) {
                enhanced_packet_block epb{file, block.block_length(), swap_byte_order};
                 datum tmp = epb.get_packet();
                 return { tmp.data, tmp.data_end };

            } else if (block.type() == interface_statistics) {
                interface_statistics_block isb{file, block.block_length(), swap_byte_order};
                isb.fprint(stderr);

            } else if (block.type() == name_resolution) {
                name_resolution_block nrb{file, block.block_length(), swap_byte_order};

            } else if (block.type() == simple_packet) {
                simple_packet_block spb{file, block.block_length(), swap_byte_order};
                 datum tmp = spb.get_packet();
                 return { tmp.data, tmp.data_end };

            } else if (block.type() == interface_description) {
                interface_description_block idb{file, block.block_length(), swap_byte_order};
                linktype = idb.get_linktype();

            } else {
                file.skip(block.block_length() - block_header::length);
            }
        }

        return { nullptr, nullptr }; // no more packets in file
    }

    enum type_code {
        interface_description = 1,
        simple_packet         = 3,
        name_resolution       = 4,
        interface_statistics  = 5,
        enhanced_packet       = 6,
    };

};

// class pcap represents a file in the PCAP (traditional Berkeley
// Packet Capture) format
//
class pcap : public pcap_reader {
    uint16_t linktype = LINKTYPE::NONE; // default
    bool swap_byte_order;
    file_datum &file;

public:

    // pcap(const char *fname) : file{fname} {

    //     pcap_file_header header{file};
    //     header.fprint(stderr);
    //     linktype = header.get_linktype();
    //     swap_byte_order = header.byteswap();

    // }

    pcap(file_datum &f) : file{f} {

        pcap_file_header header{file};
        header.fprint(stderr);
        linktype = header.get_linktype();
        swap_byte_order = header.byteswap();

    }

    enum LINKTYPE : uint16_t {
        NULL_    =   0,  // BSD loopback encapsulation
        ETHERNET =   1,  // Ethernet
        PPP      =   9,  // Point-to-Point Protocol (PPP)
        RAW      = 101,  // Raw IP; begins with IPv4 or IPv6 header
        NONE     = 65535 // reserved, used here as 'none'
    };

    const char *get_linktype() const {
        switch(linktype) {
        case LINKTYPE::NULL_:    return "NULL";
        case LINKTYPE::ETHERNET: return "ETHERNET";
        case LINKTYPE::PPP:      return "PPP";
        case LINKTYPE::RAW:      return "RAW";
        case LINKTYPE::NONE:     return "NONE";
        }
        return "unknown";
    }

    std::pair<const uint8_t *, const uint8_t *> read_packet() {

        while (file.is_not_empty()) {
            pcap_packet_record packet_record{file, swap_byte_order};
            packet_record.fprint(stderr);
            datum tmp = packet_record.get_packet();
            return tmp;
        }
        return { nullptr, nullptr }; // no more packets in file
    }

};

class file_reader {
    file_datum file;
    using reader_variant = std::variant<std::monostate, pcap, pcap_ng>;
    reader_variant reader;

    static reader_variant get_reader(file_datum &f) {

        // read four-byte file prefix to determine file type
        //
        size_t tmp = 0;
        if (f.lookahead_uint(4, &tmp) == false) {
            throw std::runtime_error("too few bytes in pcap file header");
        }

        if (tmp == section_header_block::type) {
            return reader_variant{std::in_place_type<pcap_ng>, f};

        } else if (tmp == pcap_file_header::magic || tmp == pcap_file_header::magic_nsec ) {
            return reader_variant{std::in_place_type<pcap>, f};
        }

        // error: file prefix was unrecognized
        //
        char prefix[9];
        snprintf(prefix, sizeof(prefix), "%08zx", tmp);
        std::string err_msg{"unrecognized file prefix: 0x"};
        err_msg += prefix;
        throw std::runtime_error(err_msg);
    }

    struct get_linktype_visitor {
        const char *operator()(const pcap &r)          { return r.get_linktype(); }
        const char *operator()(const pcap_ng &r)       { return r.get_linktype(); }
        const char *operator()(const std::monostate &) { return nullptr; }
    };

    struct read_packet_visitor{
        template <typename T>
        std::pair<const uint8_t *, const uint8_t *> operator()(T &r) {
            return r.read_packet();
        }
        std::pair<const uint8_t *, const uint8_t *> operator()(std::monostate &) { return { nullptr, nullptr }; }
    };

public:

    file_reader(const char *fname) : file{fname}, reader{get_reader(file)} {
    }

    enum LINKTYPE : uint16_t {
        NULL_    =   0,  // BSD loopback encapsulation
        ETHERNET =   1,  // Ethernet
        PPP      =   9,  // Point-to-Point Protocol (PPP)
        RAW      = 101,  // Raw IP; begins with IPv4 or IPv6 header
        NONE     = 65535 // reserved, used here as 'none'
    };

    const char *get_linktype() const {
        return std::visit(get_linktype_visitor{}, reader);
    }

    std::pair<const uint8_t *, const uint8_t *> read_packet() {
        return std::visit(read_packet_visitor{}, reader);
    }

    // TODO: add function that reports file version
};


}; // end of namespace pcap



#endif // PCAP_H
