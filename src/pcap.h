// pcap.h
//
// C++ header-only implementation of the PCAP-NG (Packet Capture Next
// Generation) and PCAP (traditional Berkeley Packet Capture) file
// formats

#ifndef PCAP_H
#define PCAP_H

// On Windows, we don't use mmap() for file reading, so USE_MMAP is
// defined for non-Windows platforms.
//
// On other platforms, we define the flag _O_BINARY to 0, for
// compatibility with Windows binary file mode.
//
#ifndef _WIN32
#define USE_MMAP 1
#define _O_BINARY 0
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <variant>
#include <cassert>
#include <stdexcept>

// USE_MMAP causes file reading to use mmap for improved performance;
// you should use it when it is available (Linux).
//
#ifdef USE_MMAP
#include <sys/mman.h>
#endif

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
#ifdef _WIN32
    errno_exception() : runtime_error{"errno_exception"} { };      // NOTE: could use strerr_s
#else
    errno_exception() : runtime_error{strerror_l(errno, (locale_t)0)} { };
#endif
    //  errno_exception() : runtime_error{strerror_l(errno, uselocale((locale_t)0))} { };
};

// class file_datum represents a read-only file on disk; it inherits
// the interface of class datum, and thus can be used to read and
// parse files
//
// If USE_MMAP is defined, the POSIX mmap() function is used;
// otherwise, the standard read() is used.
//
class file_datum : public datum {
    int fd = -1;
    uint8_t *addr;
    size_t file_length;

public:

    file_datum(const char *fname) : fd{open(fname, O_RDONLY|_O_BINARY)} {

        if (fd < 0) {
            throw errno_exception();
        }
        struct stat statbuf;
        if (fstat(fd, &statbuf) != 0) {
            throw errno_exception();
        }
        file_length = statbuf.st_size;
        open_data();
        data_end = data + file_length;
        addr = (uint8_t *)data;
    }

    // no copy constructor, because we own a file descriptor
    //
    file_datum(file_datum &rhs) = delete;

    ~file_datum() {
        close_data();
        if (close(fd) != 0) {
            ; // error, but don't throw errno_exception() because we are in a destructor
            assert(true && "close() failed");
        }
    }

#ifdef USE_MMAP
    void open_data() {
        data = (uint8_t *)mmap (0, file_length, PROT_READ, MAP_PRIVATE, fd, 0);
        if (data == MAP_FAILED) {
            data = data_end = nullptr;
            throw errno_exception();
        }
    }
    void close_data() {
        if (munmap(addr, file_length) != 0) {
            assert(true && "munmap() failed");
            ; // error, but don't throw errno_exception() because we are in a destructor
        }
    }
#else
    void open_data() {
        uint8_t *buf = (uint8_t *)malloc(file_length);
        if (buf == nullptr) {
            this->set_null();
            throw errno_exception();
        }
	data = buf;
        size_t bytes_read = 0;
        while (bytes_read < file_length) {
            ssize_t result = read(fd, buf, file_length - bytes_read);
            if (result == -1) {
	      throw errno_exception();
            }
            bytes_read += result;
	    buf += result;
        }
    }
    void close_data() {
        free(addr);
    }
#endif

};


//
// PCAP
//

namespace pcap {

    enum LINKTYPE : uint16_t {
        NULL_    =   0,  // BSD loopback encapsulation
        ETHERNET =   1,  // Ethernet
        PPP      =   9,  // Point-to-Point Protocol (PPP)
        RAW      = 101,  // Raw IP; begins with IPv4 or IPv6 header
        NONE     = 65535 // reserved, used here as 'none'
    };

    static const char *linktype_name(enum LINKTYPE linktype) {
        switch(linktype) {
        case LINKTYPE::NULL_:    return "NULL";
        case LINKTYPE::ETHERNET: return "ETHERNET";
        case LINKTYPE::PPP:      return "PPP";
        case LINKTYPE::RAW:      return "RAW";
        case LINKTYPE::NONE:     return "NONE";
        }
        return "unknown";
    }

    // A magic_number is a 32-bit number that indicates both the
    // endianness of the integer encoding used in a PCAP file, as well
    // as its time resolution (microseconds or nanoseconds).
    //
    class magic_values : public encoded<uint32_t> {
        bool byteswap = false;

    public:

        // The value of a Magic Number field is either 0xA1B2C3D4 or
        // 0xA1B23C4D.  If it is 0xA1B2C3D4, time stamps in Packet
        // Records are in seconds and microseconds; if it is
        // 0xA1B23C4D, time stamps in Packet Records are in seconds
        // and nanoseconds.
        //
        static constexpr uint32_t magic      = 0xa1b2c3d4;  // sec/usec
        static constexpr uint32_t magic_nsec = 0xa1b23c4d;  // sec/nsec

        magic_values(datum &d) : encoded<uint32_t>{d} {
            encoded<uint32_t> alt{*this};
            alt.swap_byte_order();

            if (*this == magic || *this == magic_nsec) {
                byteswap = false;
            } else if (alt == magic || alt == magic_nsec) {
                byteswap = true;
            } else {

                if (*this == magic_nsec || alt == magic_nsec) {
                    char errmsg_buf[34] = "unsupported file magic: ";
                    sprintf(errmsg_buf + 25, "%08x", this->value());
                    throw std::runtime_error(errmsg_buf);
                }

                char errmsg_buf[34] = "unrecognized file magic: ";
                sprintf(errmsg_buf + 25, "%08x", this->value());
                throw std::runtime_error(errmsg_buf);
            }
        }
        magic_values(uint32_t v) : encoded<uint32_t>{v} {}

        // equals_any_byte_order(rhs) compares the value of this
        // object with rhs, and returns true if and only if this
        // equals either rhs or rhs.swap_byte_order()
        //
        // this comparison is convenient for pcap logic
        //
        bool equals_any_byte_order(uint32_t rhs) const {
            encoded<uint32_t> alt{rhs};
            alt.swap_byte_order();
            return this->value() == rhs || this->value() == alt.value();
        }

        bool is_big_endian() {
            std::array<uint8_t, 4> magic{ 0xa1, 0xb2, 0xc3, 0xd4 };
            datum nbo{magic};
            encoded<uint32_t> tmp{nbo};

            return this->value() == tmp.value();
        }

        bool byteswap_needed() const { return byteswap; }
    };


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
    //   Magic Number = 0xA1B2C3D4 or 0xA1B23C4D (in any byte order)
    //   Major Version = 2
    //   Minor Version = 4
    //
    class file_header {

        magic_values magic_number;
        bool byteswap;                   // logical, not part of header format
        encoded<uint16_t> major_version;
        encoded<uint16_t> minor_version;
        ignore<uint32_t> reserved1;
        ignore<uint32_t> reserved2;
        encoded<uint32_t> snaplen;
        encoded<uint32_t> linktype;      // TODO: deal with FCS thing
        bool valid;                      // logical, not part of header format

        static constexpr ssize_t size = sizeof(uint32_t) * 7; // number of bytes in header

    public:

        file_header(datum &d) :
            magic_number{d},
            byteswap{magic_number.byteswap_needed()},
            major_version{d, byteswap},
            minor_version{d, byteswap},
            reserved1{d, byteswap},
            reserved2{d, byteswap},
            snaplen{d, byteswap},
            linktype{d, byteswap},
            valid{d.is_not_null()}
        {
            // fprintf(stderr, "is_big_endian: %u\n", magic_number.is_big_endian());
        }

        // constructor for writing file_header
        //
        file_header(uint32_t snap, uint16_t lt) :
            magic_number{magic_values::magic},
            byteswap{false},
            major_version{2},
            minor_version{4},
            snaplen{snap},
            linktype{lt},
            valid{true}
        { }

        void write(writeable &buf) {

            if (!valid) {
                buf.set_empty();  // TODO: indicate failure
                return;
            }

            buf << magic_number
                << major_version
                << minor_version
                << reserved1
                << reserved2
                << snaplen
                << linktype;

        }

        void fprint(FILE *f) {
            fprintf(f, "magic_number: %x\n", magic_number.value());
            fprintf(f, "major_version: %u\n", major_version.value());
            fprintf(f, "minor_version: %u\n", minor_version.value());
            fprintf(f, "snaplen: %u\n", snaplen.value());
            fprintf(f, "linktype: %u\n", linktype.value());
        }

        uint32_t get_linktype() const { return linktype; }

        bool byteswap_needed() const { return byteswap; }

        static bool is_magic(uint32_t x) {
            magic_values mx{x};
            return mx.equals_any_byte_order(magic_values::magic) || mx.equals_any_byte_order(magic_values::magic_nsec);
        }

        std::pair<uint16_t, uint16_t> get_version() const {
            return { major_version, minor_version };
        }

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
    class packet_record {
        encoded<uint32_t> timestamp_sec;
        encoded<uint32_t> timestamp_usec;
        encoded<uint32_t> caplen;
        encoded<uint32_t> len;
        datum packet_data;

    public:

        packet_record(datum &d, bool swap_byte_order) :
            timestamp_sec{d, swap_byte_order},
            timestamp_usec{d, swap_byte_order},
            caplen{d, swap_byte_order},
            len{d, swap_byte_order},
            packet_data{d, caplen}
        {  }

        packet_record(uint32_t ts_sec,
                           uint32_t ts_usec,
                           datum pkt) :
            timestamp_sec{ts_sec},
            timestamp_usec{ts_usec},
            caplen{static_cast<uint32_t>(pkt.length())},
            len{static_cast<uint32_t>(pkt.length())},
            packet_data{pkt}
        { }

        bool is_valid() const { return packet_data.is_not_null(); }

        void write(writeable &buf) {

            if (!is_valid()) {
                buf.set_empty();  // TODO: indicate failure
                // fprintf(stderr, "error in %s\n", __func__);
                return;
            }

            buf << timestamp_sec
                << timestamp_usec
                << caplen
                << len
                << packet_data;

        }

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


    // class pcap::base_pcap_reader reads packet capture files in either the
    // PCAP (traditional Berkeley Packet Capture) format or PCAP-NG (PCAP
    // Next Generation) format.  It is implemented as an abstract base
    // class, whose derived classes are readers for those two formats.
    //
    class base_pcap_reader {

    public:

        virtual const char *get_linktype() const = 0;

        virtual std::pair<const uint8_t *, const uint8_t *> read_packet() = 0;

    };

    
    class file_writer {
        int fd;
        uint16_t linktype = LINKTYPE::NONE; // default

        static constexpr size_t snaplen = 1024 * 4;

    public:

        file_writer(const char *fname, uint16_t ltype=LINKTYPE::ETHERNET) :
            fd{open(fname, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)},
            linktype{ltype}
        {
            if (fd < 0) {
                throw errno_exception();
            }

            data_buffer<1024 * 8> buf;
            file_header header(snaplen, ltype);

            header.write(buf);
            buf.write(fd);

        }

        void write(datum pkt) {
            packet_record record{0, 0, pkt};
            data_buffer<1024 * 8> buf;
            record.write(buf);
            buf.write(fd);
        }

        enum LINKTYPE get_linktype() const { return (enum LINKTYPE)linktype; }

    };

    // class pcap::reader represents a file in the PCAP (traditional
    // Berkeley Packet Capture) format
    //
    class reader : public base_pcap_reader {
        uint16_t linktype = LINKTYPE::NONE; // default
        bool swap_byte_order;
        file_datum &file;
        std::pair<uint16_t, uint16_t> version = { 0, 0 };

    public:

        reader(file_datum &f) : file{f} {
            file_header header{file};
            // header.fprint(stderr);
            linktype = header.get_linktype();
            swap_byte_order = header.byteswap_needed();
            version = header.get_version();
        }

        const char *get_linktype() const {
            return linktype_name((enum LINKTYPE)linktype);
        }

        std::pair<const uint8_t *, const uint8_t *> read_packet() {

            while (file.is_not_empty()) {
                packet_record record{file, swap_byte_order};
                return record.get_packet();
            }
            return { nullptr, nullptr }; // no more packets in file
        }

        std::pair<uint16_t, uint16_t> get_version() const {
            return version;
        }

    };

}; // end of namespace pcap

// namespace ng implements the "Next Generation" format
//
namespace pcap::ng {

    //
    // PCAP-NG (Next Generation)
    //

    enum type_code {
        interface_description = 1,
        simple_packet         = 3,
        name_resolution       = 4,
        interface_statistics  = 5,
        enhanced_packet       = 6,
    };

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
        { }

        // constructor for writing block_headers
        //
        block_header(uint32_t type, uint32_t block_total_len) :
            block_type{type},
            block_total_length{block_total_len}
        { }

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

        void write(writeable &buf) {
            buf << block_type
                << block_total_length;
        }

    };

    // class pcap::ng::block_footer represents a (possibly empty)
    // options field and the trailing block_total_length field, which
    // are the final two fields of several block types
    //
    class block_footer {
        datum options;

    public:

        block_footer(datum &d, size_t options_length, bool byteswap_needed) {

            options.parse(d, options_length);
            uint32_t block_total_length;
            d.read_uint32(&block_total_length);
            if (byteswap_needed) {
                block_total_length = swap_byte_order(block_total_length);
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
        encoded<uint16_t> code;
        encoded<uint16_t> length;
        datum value;
        pad padding;

    public:

        option(datum &d, bool byteswap) :
            code{d, byteswap},
            length{d, byteswap},
            value{d, length},
            padding{d, pad_len(length)}
        {
            // fprintf(stderr, "%s\n", __func__);
            // fprintf(stderr, "code:   %u\n", code.value());
            // fprintf(stderr, "length: %u\n", length.value());
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
        encoded<uint32_t> block_type;
        encoded<uint32_t> block_total_length;
        encoded<uint32_t> magic;
        encoded<uint16_t> major_version;
        encoded<uint16_t> minor_version;
        encoded<uint64_t> section_length;
        datum options;
        bool byteswap_needed = false;

        static constexpr size_t non_option_length = 28;

    public:

        static constexpr uint32_t type = 0x0a0d0d0a;

        section_header_block(datum &d) :
            block_type{d},
            block_total_length{d},
            magic{d},
            major_version{d},
            minor_version{d},
            section_length{d}
        {
            // fprintf(stderr, "%s\n", __func__);

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
                block_total_length.swap_byte_order();
                major_version.swap_byte_order();
                minor_version.swap_byte_order();
                section_length.swap_byte_order();
            }

            ssize_t options_length = block_total_length - non_option_length;
            options.parse(d, options_length);

            uint32_t tmp;
            d.read_uint32(&tmp); // second block_length; ignore for now

            // fprintf(stderr, "byteswap_needed:    %u\n", byteswap_needed);
            // fprintf(stderr, "block_type:         %x\n", block_type.value());
            // fprintf(stderr, "block_total_length: %u\n", block_total_length.value());
            // fprintf(stderr, "magic:              %x\n", magic.value());
            // fprintf(stderr, "major_version:      %u\n", major_version.value());
            // fprintf(stderr, "minor_version:      %u\n", minor_version.value());
            // fprintf(stderr, "section_length:     %lx\n", section_length.value());
            // fprintf(stderr, "options_length:     %lx\n", options_length);
            // options.fprint_hex(stderr); fputc('\n', stderr);

            while (options.is_not_empty()) {
                option opt{options, byteswap_needed};
                // opt.fprint(stderr);
            }

	    // fprintf(stderr, "data length: %zu\n", d.length());
            // d.fprint_hex(stderr); fputc('\n', stderr);
        }

        static constexpr uint64_t length_unspecified = 0xffffffffffffffff;

        section_header_block() :
            block_type{type},
            block_total_length{non_option_length}, // no options present
            magic{0x1a2b3c4d},
            major_version{1},
            minor_version{0},
            section_length{length_unspecified}
        { }

        void write(writeable &buf) {

            // if (!valid) {
            //     buf.set_empty();  // TODO: indicate failure
            //     return;
            // }

            buf << block_type
                << block_total_length
                << magic
                << major_version
                << minor_version
                << section_length
                // note: no options are written
                << block_total_length;  // footer; duplicates earlier value
        }

        bool byteswap() const { return byteswap_needed; }

        std::pair<uint16_t, uint16_t> get_version() const {
            return { major_version, minor_version };
        }

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
        encoded<uint16_t> linktype;
        encoded<uint16_t> reserved;
        encoded<uint32_t> snaplen;
        datum options;

        static constexpr size_t non_option_length = 20;

    public:

        interface_description_block(datum &d, ssize_t block_total_length, bool byteswap_needed) :
            linktype{d, byteswap_needed},
            reserved{d, byteswap_needed},
            snaplen{d, byteswap_needed}
        {
            // fprintf(stderr, "%s\n", __func__);

            if (d.is_null()) {
                return;
            }

            // if (byteswap_needed) {
            //     linktype = ntohs(linktype);
            //     snaplen = ntohl(snaplen);
            // }

            ssize_t options_length = block_total_length - non_option_length;
            options.parse(d, options_length);

            uint32_t tmp;
            d.read_uint32(&tmp); // second block_length; ignore for now

            // fprintf(stderr, "byteswap_needed:    %u\n", byteswap_needed);
            // fprintf(stderr, "linktype:           %u\n", linktype.value());
            // fprintf(stderr, "reserved:           %u\n", reserved.value());
            // fprintf(stderr, "snaplen:            %u\n", snaplen.value());
            // fprintf(stderr, "options_length:     %lx\n", options_length);
            // options.fprint_hex(stderr); fputc('\n', stderr);

            while (options.is_not_empty()) {
                option opt{options, byteswap_needed};
                //            opt.fprint(stderr);
            }

            // fprintf(stderr, "data length: %zu\n", d.length());
            //  d.fprint_hex(stderr); fputc('\n', stderr);

        }

        // constructor for writing interface description block
        //
        interface_description_block(LINKTYPE ltype, uint16_t snap, bool byteswap_needed=false) :
            linktype{ltype},
            reserved{byteswap_needed},
            snaplen{snap}
        {}

        uint16_t get_linktype() const { return linktype; }

        void write(writeable &buf) {
            encoded<uint32_t> block_total_length = non_option_length;
            buf << block_header{interface_description, block_total_length}
                << linktype
                << reserved
                << snaplen
                // << options          // TODO: allow option writing
                << block_total_length; // footer
        }
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
        encoded<uint32_t> addr;
        datum strings;

    public:

        nrb_record_ipv4(datum &d) : addr{d} {
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
        encoded<uint16_t> record_type;
        encoded<uint16_t> record_value_length;
        datum value;
        pad padding;

    public:

        name_resolution_record(datum &d, bool byteswap_needed) :
            record_type{d, byteswap_needed},
            record_value_length{d, byteswap_needed},
            value{d, record_value_length},
            padding{d, pad_len(record_value_length)}
        {
            // fprintf(stderr, "%s\n", __func__);
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
            // fprintf(stderr, "%s\n", __func__);
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
                    // ipv4.fprint(stderr); fputc('\n', stderr);
                }
                if (nrr.get_type() == name_resolution_record::type::ipv6) {
                    datum value = nrr.get_value();
                    nrb_record_ipv6 ipv6{value};
                    // ipv6.fprint(stderr); fputc('\n', stderr);
                }
            }

            size_t options_length = block_length - records_length - fixed_fields_length;
            // fprintf(stderr, "options_length: %zu\n", options_length);
            // d.fprint_hex(stderr); fputc('\n', stderr);
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

        encoded<uint32_t> interface_id;
        encoded<uint32_t> timestamp_hi;
        encoded<uint32_t> timestamp_lo;
        encoded<uint32_t> caplen;
        encoded<uint32_t> len;
        datum packet;
        pad padding;

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

        enhanced_packet_block(datum &d, size_t block_length, bool byteswap_needed) :
            interface_id{d, byteswap_needed},
            timestamp_hi{d, byteswap_needed},
            timestamp_lo{d, byteswap_needed},
            caplen{d, byteswap_needed},
            len{d, byteswap_needed},
            packet{d, caplen},
            padding{d, pad_len(caplen)}
        {
            // fprintf(stderr, "%s\n", __func__);
            // fprintf(stderr, "interface_id: %u\n", interface_id.value());
            // fprintf(stderr, "timestamp_hi: %u\n", timestamp_hi.value());
            // fprintf(stderr, "timestamp_lo: %u\n", timestamp_lo.value());
            // fprintf(stderr, "caplen: %u\n", caplen.value());
            // fprintf(stderr, "len: %u\n", len.value());
            packet.fprint_hex(stderr); fputc('\n', stderr);

            ssize_t options_length = block_length - fixed_length - (caplen + pad_len(caplen));
            block_footer footer{d, options_length, byteswap_needed};

        }

        enhanced_packet_block(datum &pkt,
                              uint32_t interface,
                              uint32_t t_hi,
                              uint32_t t_lo) :
            interface_id{interface},
            timestamp_hi{t_hi},
            timestamp_lo{t_lo},
            caplen{pkt.length()},
            len{pkt.length()},   // NOTE: always equals caplen
            packet{pkt},
            padding{pad_len(pkt.length())}
        { }

        datum get_packet() const {
            return packet;
        }

        void write(writeable &buf) const {
            encoded<uint32_t> block_total_length = fixed_length + packet.length() + pad_len(packet.length());
            buf << block_header{enhanced_packet, block_total_length}
                << interface_id
                << timestamp_hi
                << timestamp_lo
                << caplen
                << len
                << packet
                << padding
                << block_total_length;

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
        encoded<uint32_t> original_packet_length;
        datum packet;
        pad padding;

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

        simple_packet_block(datum &d, size_t block_length, bool byteswap_needed) :
            original_packet_length{d, byteswap_needed},
            packet{d, block_length - fixed_length},
            padding{d, pad_len(block_length - fixed_length)}
        {
            // fprintf(stderr, "%s\n", __func__);

            // fprintf(stderr, "caplen: %zd\n", block_length - fixed_length);
            // fprintf(stderr, "original_packet_length: %u\n", original_packet_length.value());
            // packet.fprint_hex(stderr); fputc('\n', stderr);

            ignore<uint32_t> trailing_block_total_length{d};
        }

        simple_packet_block(datum &pkt) :
            original_packet_length{pkt.length()},
            packet{pkt},
            padding{pad_len(pkt.length())}
        { }

        datum get_packet() const {
            return packet;
        }

        void write(writeable &buf) const {
            encoded<uint32_t> block_total_length = fixed_length + packet.length() + pad_len(packet.length());
            buf << block_header{simple_packet, block_total_length}
                << original_packet_length
                << packet
                << padding
                << block_total_length;
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
        encoded<uint32_t> timestamp_hi;
        encoded<uint32_t> timestamp_lo;

    public:

        isb_starttime(datum &d, bool byteswap) :
            timestamp_hi{d, byteswap},
            timestamp_lo{d, byteswap}
        {
            // fprintf(stderr, "%s\n", __func__);
        }

        void fprint(FILE *f) const {
            fprintf(f, "timestamp_hi: %u\n", timestamp_hi.value());
            fprintf(f, "timestamp_lo: %u\n", timestamp_lo.value());
        }
    };

    // The isb_endtime option specifies the time the capture ended; time
    // will be stored in two blocks of four octets each. The format of the
    // timestamp is the same as the one defined in the Enhanced Packet
    // Block (Section 4.3); the length of a unit of time is specified by
    // the 'if_tsresol' option (see Figure 10) of the Interface
    // Description Block referenced by this packet.

    class isb_endtime {
        encoded<uint32_t> timestamp_hi;
        encoded<uint32_t> timestamp_lo;

    public:

        isb_endtime(datum &d, bool byteswap) :
            timestamp_hi{d, byteswap},
            timestamp_lo{d, byteswap}
        {
            // fprintf(stderr, "%s\n", __func__);
        }

        void fprint(FILE *f) const {
            fprintf(f, "timestamp_hi: %u\n", timestamp_hi.value());
            fprintf(f, "timestamp_lo: %u\n", timestamp_lo.value());
        }
    };


    //    The isb_ifrecv option specifies the 64-bit unsigned integer
    //    number of packets received from the physical interface starting
    //    from the beginning of the capture.
    //
    class isb_ifrecv {
        encoded<uint64_t> count;

    public:

        isb_ifrecv(datum &d, bool byteswap) :
            count{d, byteswap}
        {
            // fprintf(stderr, "%s\n", __func__);
        }

        void fprint(FILE *f) const {
            fprintf(f, "count: %lu\n", count.value());
        }
    };

    //    The isb_ifdrop option specifies the 64-bit unsigned integer
    //    number of packets dropped by the interface due to lack of
    //    resources starting from the beginning of the capture.
    //
    class isb_ifdrop {
        encoded<uint64_t> count;

    public:

        isb_ifdrop(datum &d, bool byteswap) :
            count{d, byteswap}
        {
            // fprintf(stderr, "%s\n", __func__);
        }

        void fprint(FILE *f) const {
            fprintf(f, "count: %lu\n", count.value());
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
        encoded<uint32_t> interface_id;
        encoded<uint32_t> timestamp_hi;
        encoded<uint32_t> timestamp_lo;
        datum options;
        bool swap_byte_order;

        // fixed_length is the sum of the lengths of all of the fixed fields
        // (that is, all fields except the options)
        //
        static constexpr size_t fixed_length = 24;

    public:

        interface_statistics_block(datum &d, size_t block_length, bool byteswap) :
            interface_id{d, byteswap},
            timestamp_hi{d, byteswap},
            timestamp_lo{d, byteswap}
        {
            // fprintf(stderr, "%s\n", __func__);

            ssize_t options_length = block_length - fixed_length;
            options.parse(d, options_length);
            swap_byte_order = byteswap;
            d.skip(4);  // final block total length field
            //        block_footer footer{d, options_length, byteswap};
        }

        void fprint(FILE *f) const {
            fprintf(f, "interface_id: %u\n", interface_id.value());
            fprintf(f, "timestamp_hi: %u\n", timestamp_hi.value());
            fprintf(f, "timestamp_lo: %u\n", timestamp_lo.value());

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

    // class pcap::ng::reader represents a file reader for the PCAP-NG
    // (Packet Capture Next Generation) format
    //
    class reader : public base_pcap_reader {
        uint16_t linktype = LINKTYPE::NONE; // default
        bool swap_byte_order;
        file_datum &file;
        std::pair<uint16_t, uint16_t> version = { 0, 0 };

    public:

        reader(file_datum &f) : file{f} {
            section_header_block shb{file};
            swap_byte_order = shb.byteswap();
            version = shb.get_version();

            block_header block{file, swap_byte_order};
            // fprintf(stderr, "got block with type %u and length %u\n", block.type(), block.block_length());
            interface_description_block idb{file, block.block_length(), swap_byte_order};
            linktype = idb.get_linktype();

            //
            // TODO: advance up to packet block
            //
        }

        const char *get_linktype() const {
            return linktype_name((enum LINKTYPE)linktype);
        }

        std::pair<const uint8_t *, const uint8_t *> read_packet() {

            while (file.is_not_empty()) {
                block_header block{file, swap_byte_order};
                // fprintf(stderr, "got block with type %u and length %u\n", block.type(), block.block_length());
                // file.fprint_hex(stderr, block.block_length() - block_header::length); fputc('\n', stderr);
                if (block.block_length() == 0) {
                    break;
                }
                if (block.type() == enhanced_packet) {
                    enhanced_packet_block epb{file, block.block_length(), swap_byte_order};
                    datum tmp = epb.get_packet();
                    return { tmp.data, tmp.data_end };

                } else if (block.type() == interface_statistics) {
                    interface_statistics_block isb{file, block.block_length(), swap_byte_order};
                    isb.fprint(stdout);

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

        std::pair<uint16_t, uint16_t> get_version() const {
            return version;
        }
    };

    // class pcap::ng::file_writer implements a file writer for the
    // PCAP-NG format
    //
    class file_writer {
        int fd;
        uint16_t linktype = LINKTYPE::NONE; // default

        static constexpr size_t snaplen = 1024 * 8;

    public:

        file_writer(const char *fname, pcap::LINKTYPE ltype=LINKTYPE::ETHERNET) :
            fd{open(fname, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)},
            linktype{ltype}
        {
            if (fd < 0) {
                throw errno_exception();
            }

            data_buffer<snaplen> buf;
            section_header_block file_header;
            file_header.write(buf);
            interface_description_block idb{ltype, snaplen};
            idb.write(buf);
            buf.write(fd);

        }

        void write(datum pkt) {
            data_buffer<1024 * 8> buf;
            simple_packet_block packet_block{pkt};
            packet_block.write(buf);
            buf.write(fd);
        }

        void write(datum pkt,
                   uint32_t interface,
                   uint32_t t_hi,
                   uint32_t t_lo) {
            data_buffer<1024 * 8> buf;
            enhanced_packet_block packet_block{pkt, interface, t_hi, t_lo};
            packet_block.write(buf);
            buf.write(fd);
        }

        enum LINKTYPE get_linktype() const { return (enum LINKTYPE)linktype; }

    };

} // end of namespace pcap::ng

namespace pcap {

    class file_reader {
        file_datum file;
        using reader_variant = std::variant<std::monostate, pcap::reader, pcap::ng::reader>;
        reader_variant rdr;

        static reader_variant get_reader(file_datum &f) {

            // read four-byte file prefix to determine file type
            //
            size_t tmp = 0;
            if (f.lookahead_uint(4, &tmp) == false) {
                throw std::runtime_error("too few bytes in pcap file header");
            }

            if (tmp == ng::section_header_block::type) {
                return reader_variant{std::in_place_type<ng::reader>, f};

            } else if (file_header::is_magic(tmp)) {
                return reader_variant{std::in_place_type<reader>, f};
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
            const char *operator()(const pcap::reader &r)     { return r.get_linktype(); }
            const char *operator()(const pcap::ng::reader &r) { return r.get_linktype(); }
            const char *operator()(const std::monostate &)    { return nullptr; }
        };

        struct read_packet_visitor{
            template <typename T>
            std::pair<const uint8_t *, const uint8_t *> operator()(T &r) {
                return r.read_packet();
            }
            std::pair<const uint8_t *, const uint8_t *> operator()(std::monostate &) { return { nullptr, nullptr }; }
        };

        struct get_version_visitor {
            template<typename T>
            std::pair<uint16_t, uint16_t> operator()(T &r) {
                return r.get_version();
            }
            std::pair<uint16_t, uint16_t> operator()(std::monostate &) {
                return { 0, 0 };
            }
        };

        struct get_format_visitor {
            const char *operator()(const pcap::reader &) {
                return "PCAP";
            }
            const char *operator()(const pcap::ng::reader &) {
                return "PCAPNG";
            }
            const char *operator()(const std::monostate &) {
                return "unknown";
            }
        };

    public:

        file_reader(const char *fname) : file{fname}, rdr{get_reader(file)} { }

        const char *get_format() const {
            return std::visit(get_format_visitor{}, rdr);
        }

        const char *get_linktype() const {
            return std::visit(get_linktype_visitor{}, rdr);
        }

        std::pair<const uint8_t *, const uint8_t *> read_packet() {
            return std::visit(read_packet_visitor{}, rdr);
        }

        std::pair<uint16_t, uint16_t> get_version() {
            return std::visit(get_version_visitor{}, rdr);
        }

    };

}; // end of namespace pcap

#endif // PCAP_H
