// archive.h
//
// tape archive (tar) reader


#ifndef ARCHIVE_H
#define ARCHIVE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include <fstream>
#include <vector>
#include <string>

#include <zlib.h>

#include "libmerc.h"
#include "datum.h"

// for debugging

void fprintf_raw_as_hex(FILE *f, const uint8_t *data, unsigned int len);
#if 0
void fprintf_raw_as_hex(FILE *f, const uint8_t *data, unsigned int len) {
    const unsigned char *x = data;
    const unsigned char *end = data + len;

    while (x < end) {
        fprintf(f, "%02x", *x++);
    }
}
#endif

#define print_field(f, F) fprintf(f, #F ":\t%.*s\n", (int)sizeof(F), F)

class archive_node {

    // definitions used in typeflags
    //
    enum archive_entry_type : unsigned char {
        REGTYPE    = '0',  // regular file (preferred)
        AREGTYPE   = '\0', // regular file (alternate)
        LNKTYPE    = '1',  // hard link
        SYMTYPE    = '2',  // symbolic link
        CHRTYPE    = '3',  // character special
        BLKTYPE    = '4',  // block special
        DIRTYPE    = '5',  // directory
        FIFOTYPE   = '6',  // named pipe
        CONTTYPE   = '7',  // contiguous file
    };

public:

    void print_all_fields(FILE *f) const {

        print_field(f, name);
        print_field(f, mode);
        print_field(f, uid);
        print_field(f, gid);
        print_field(f, size);
        print_field(f, mtime);
        print_field(f, chksum);
        print_field(f, typeflag);
        print_field(f, linkname);
        print_field(f, magic);
        print_field(f, version);
        print_field(f, uname);
        print_field(f, gname);
        print_field(f, devmajor);
        print_field(f, devminor);
        print_field(f, prefix);
        fprintf(f, "size: %zu bytes\n", get_size());
    }

    void print(FILE *f) const {
        print_field(f, name);
        fprintf(f, "size: %zu bytes\n", get_size());
    }

    size_t get_size() const {
        return strtoull(size, NULL, 8);
    }

    const char *get_name() const {
        return name;   // TBD: insist on null-termination?
    }

    size_t bytes_until_next_block() const {
        size_t l = get_size();
        return l + (-l & 511);  // round up to multiple of 512
    }

    bool is_valid() const {
        if (memcmp(magic, "ustar", sizeof(magic)-1) == 0) {
            return true;
        }
        return false;
    }

    bool is_directory() const {
        if (typeflag[0] == archive_entry_type::DIRTYPE) {
            return true;
        }
        return false;
    }

    bool is_regular_file() const {
        if (typeflag[0] == archive_entry_type::REGTYPE) {
            return true;
        }
        return false;
    }

    unsigned char get_type_flag() const {
        return typeflag[0];
    }

private:
    char name    [100]; // \0 terminated (if \0 fits)
    char mode    [8];
    char uid     [8];
    char gid     [8];
    char size    [12];
    char mtime   [12];
    char chksum  [8];
    char typeflag[1];
    char linkname[100]; // \0 terminated (if \0 fits)
    char magic   [6];   // "ustar" (\0 terminated ??)
    char version [2];   //  "00" ??
    char uname   [32];  // \0 terminated
    char gname   [32];  // \0 terminated
    char devmajor[8];
    char devminor[8];
    char prefix  [155]; // \0 terminated (if \0 fits)
};

class archive {
private:
    FILE *file;
    class archive_node *entry;
    char buffer[512];

public:
    archive(const char *filename) : file{nullptr}, entry{nullptr} {
        file = fopen(filename, "r");
        if (file == nullptr) {
            fprintf(stderr, "error: could not open archive file %s\n", filename);
        }
        // note: file may be nullptr after construction
    }

    class archive_node *get_next_entry() {

        if (file == nullptr) {
            return nullptr;   // error; not reading an archive file
        }

        if (entry != nullptr) {

            // advance to next block
            if (fseek(file, entry->bytes_until_next_block(), SEEK_CUR) == -1) {
                fprintf(stderr, "error: attempt to advance %zu bytes in archive file failed\n", entry->get_size());
                return nullptr;
            }
        }

        size_t bytes_read = fread(buffer, 1, sizeof(buffer), file);
        if (bytes_read != sizeof(buffer)) {
            fprintf(stderr, "error: attempt to read %zu bytes from archive file failed\n", sizeof(buffer));
            return nullptr;
        }
        entry = (class archive_node *)buffer;
        if (!entry->is_valid()) {
            return nullptr;
        }
        return entry;
    }

};

class compressed_archive {
private:
    gzFile file;
    class archive_node *entry;
    char buffer[512];
    ssize_t next_entry;
    ssize_t end_of_file;
    int fd;

public:

    ssize_t next_entry_value() const { return next_entry; }

    compressed_archive(const char *filename) : file{nullptr}, entry{nullptr}, next_entry{0}, end_of_file{0}, fd{0} {
        fd = open(filename, O_RDONLY, "r");
        file = gzdopen(fd, "r");
        if (file == nullptr) {
            fprintf(stderr, "error: could not open archive file %s\n", filename);
        }
        // note: file may be nullptr after construction
    }

    ~compressed_archive() {
        if (file) {
            gzclose(file);
        }
        if (fd) {
            close(fd);
        }
    }

    class archive_node *get_next_entry() {

        if (file == nullptr) {
            return nullptr;   // error; not reading a compressed archive file
        }

        if (entry != nullptr) {

            // advance to next block
            if (gzseek(file, next_entry, SEEK_SET) == -1) {
                fprintf(stderr, "error: could not advance %zu bytes in archive file\n", entry->get_size());
                return nullptr;
            }
        }

        return read_block();
    }

    class archive_node *read_block() {
        ssize_t bytes_read = gzread(file, buffer, sizeof(buffer));
        if (bytes_read != (ssize_t)sizeof(buffer)) {
            fprintf(stderr, "error: attempt to read %zu bytes from archive file failed\n", sizeof(buffer));
            return nullptr;
        }
        entry = (class archive_node *)buffer;
        if (!entry->is_valid()) {
            return nullptr;
        }
        next_entry = entry->bytes_until_next_block() + gztell(file);
        end_of_file = entry->get_size() + gztell(file);
        return entry;
    }

    ssize_t getline(std::string &s) {
        s.clear();
        char read_buffer[8192];
        while (true) {

            ssize_t read_len = sizeof(read_buffer);
            if (read_len + gztell(file) > end_of_file) {
                read_len = end_of_file - gztell(file);
            }
            if (read_len == 0) {
                break;  // no more data
            }
            if (gzgets(file, read_buffer, read_len) == NULL) {
                return s.length();     // EOF
            }
            size_t bytes_read = strlen(read_buffer);
            s.append(read_buffer, bytes_read);
            if (bytes_read > 0 && read_buffer[bytes_read-1] == '\n') {
                s.erase(s.length()-1);   // strip terminating newline
                break;
            }
        }
        return s.length();
    }

};

static void *_zalloc(void *, unsigned n, unsigned m) {
    return calloc(n, m);
}

static void _zfree(void *, void *p) {
    free(p);
}

struct uint8_bitfield_ {
    uint8_t value;

    uint8_bitfield_(uint8_t x) : value{x} {}

    void fprint(FILE *f) {
        for (uint8_t x = 0x80; x > 0; x=x>>1) {
            if (x & value) {
                fputc('1', f);
            } else {
                fputc('0', f);
            }
        }
    }
};

class deflate_header {
public:
    uint8_t compression_method;
    uint8_bitfield_ flags;
    uint32_t mtime;
    bool valid;
    uint8_t xfl;
    uint8_t os;

    deflate_header(struct datum &d) : compression_method{0}, flags{0}, valid{false} {
        uint8_t id_1;
        uint8_t id_2;

        d.read_uint8(&id_1);
        d.read_uint8(&id_2);
        if (id_1 != 0x1f || id_2 != 0x8b) {
            return; // error: mismatch
        }
        d.read_uint8(&compression_method);
        d.read_uint8(&flags.value);
        d.read_uint32(&mtime);
        mtime = ntohl(mtime);
        d.read_uint8(&xfl);
        d.read_uint8(&os);

    }

    void fprint(FILE *f) {
        fprintf(f, "compression_method: %u\n", compression_method);
        fprintf(f, "flags: ");
        flags.fprint(f);
        fputc('\n', f);
        fprintf(f, "mtime: %u\n", mtime);
        fprintf(f, "xfl: %u\n", xfl);
        fprintf(f, "os: %u\n", os);
    }
};

class encrypted_compressed_archive {
private:
    //    gzFile file;
    class archive_node *entry;
    unsigned char buffer[512];
    ssize_t next_entry;
    ssize_t end_of_file;
    int fd;
    unsigned char file_buffer[512];
    z_stream_s z;

public:

    ssize_t next_entry_value() const { return next_entry; }

    bool get_bytes() {
        while (true) {

            fprintf(stderr, "avail_in: %u\tavail_out: %u\n", z.avail_in, z.avail_out);

            int err = inflate(&z, Z_NO_FLUSH);
            fprintf(stderr, "got error code %d (message: %s)\n", err, z.msg);
            fprintf(stderr, "z.avail_in: %u\n", z.avail_in);
            fprintf(stderr, "z.avail_out: %u\n", z.avail_out);
            if (err != Z_OK || err == Z_STREAM_END) {
                fprintf(stderr, "error: could not initialize zlib decompressor\n");
                return false;
            }

            // dump buffer
            fprintf(stdout, "buffer:      '%.*s'\n", z.avail_out, buffer);
            fprintf_raw_as_hex(stderr, buffer, z.avail_out);
            fputc('\n', stderr);
            z.next_out = buffer;
            z.avail_out = sizeof(buffer);

            // fprintf(stderr, "z.avail_in: %u\n", z.avail_in);
            if (z.avail_in == 0) {
                ssize_t file_buffer_bytes = read(fd, file_buffer, sizeof(file_buffer));
                if (file_buffer_bytes < 0) { // (ssize_t)sizeof(file_buffer)) {
                    fprintf(stderr, "error: could not read archive file (%ld)\n", file_buffer_bytes);
                    return false;  // error; not reading a compressed archive file
                }
                z.next_in = file_buffer;
                z.avail_in = file_buffer_bytes;
            }
        }

    }

    encrypted_compressed_archive(const char *filename) : entry{nullptr}, next_entry{0}, end_of_file{0}, fd{0} {
        fd = open(filename, O_RDONLY, "r");
        if (fd == 0) {
            fprintf(stderr, "error: could not open archive file %s\n", filename);
            return;  // error; not reading a compressed archive file
        }
        //file = gzdopen(fd, "r");

#if 0
        // read 0x1f8d header
        ssize_t file_buffer_bytes = read(fd, file_buffer, 10);
        if (file_buffer_bytes < 10) {
            fprintf(stderr, "error: could not read deflate header from archive file %s (%ld)\n", filename, file_buffer_bytes);
            return;  // error; not reading a compressed archive file
        }
        fprintf_raw_as_hex(stderr, file_buffer, file_buffer_bytes);
        fputc('\n', stderr);

        struct datum file_header{file_buffer, file_buffer+10};
        deflate_header dh{file_header};
        dh.fprint(stderr);
#endif
        ssize_t file_buffer_bytes = read(fd, file_buffer, sizeof(file_buffer));
        if (file_buffer_bytes < 0) { // (ssize_t)sizeof(file_buffer)) {
            fprintf(stderr, "error: could not read archive file %s (%ld)\n", filename, file_buffer_bytes);
            return;  // error; not reading a compressed archive file
        }

        fprintf(stderr, "read %zd bytes from file\n", file_buffer_bytes);
        fprintf(stderr, "file_buffer: '%.*s'\n", (int)file_buffer_bytes, file_buffer);
        fprintf_raw_as_hex(stderr, file_buffer, file_buffer_bytes);
        fputc('\n', stderr);

        //  set next_in, avail_in, zalloc, zfree and opaque
        z.next_in = file_buffer;
        z.avail_in = file_buffer_bytes;
        z.zalloc = _zalloc;
        z.zfree = _zfree;
        z.opaque = nullptr; // ???
        z.next_out = buffer;
        z.avail_out = sizeof(buffer);

        // int err = inflateInit(&z);
        int err = inflateInit2(&z, 16+MAX_WBITS); // see zlib.h version 1.2.1
        if (err != Z_OK) {
            fprintf(stderr, "error in InflateInit (code %d)\n", err);
        }
        while (true) {

            fprintf(stderr, "avail_in: %u\tavail_out: %u\n", z.avail_in, z.avail_out);

            int err = inflate(&z, Z_NO_FLUSH);
            fprintf(stderr, "got error code %d (message: %s)\n", err, z.msg);
            fprintf(stderr, "z.avail_in: %u\n", z.avail_in);
            fprintf(stderr, "z.avail_out: %u\n", z.avail_out);
            if (err != Z_OK || err == Z_STREAM_END) {
                fprintf(stderr, "error: could not initialize zlib decompressor\n");
                return;
            }

            // dump buffer
            fprintf(stdout, "buffer:      '%.*s'\n", z.avail_out, buffer);
            fprintf_raw_as_hex(stderr, buffer, z.avail_out);
            fputc('\n', stderr);
            z.next_out = buffer;
            z.avail_out = sizeof(buffer);

            // fprintf(stderr, "z.avail_in: %u\n", z.avail_in);
            if (z.avail_in == 0) {
                file_buffer_bytes = read(fd, file_buffer, sizeof(file_buffer));
                if (file_buffer_bytes < 0) { // (ssize_t)sizeof(file_buffer)) {
                    fprintf(stderr, "error: could not read archive file %s (%ld)\n", filename, file_buffer_bytes);
                    return;  // error; not reading a compressed archive file
                }
                z.next_in = file_buffer;
                z.avail_in = file_buffer_bytes;
            }
        }

        return;
        fprintf(stderr, "buffer:      '%.*s'\n", (int)sizeof(buffer), buffer);
        fprintf_raw_as_hex(stderr, buffer, sizeof(buffer));
        fputc('\n', stderr);

        // note: file may be nullptr after construction
    }

    ~encrypted_compressed_archive() {
        if (fd) {
            close(fd);
        }
    }

    class archive_node *get_next_entry() {

        if (fd == 0) {
            return nullptr;   // error; not reading a compressed archive file
        }

#if 0
        if (entry != nullptr) {

            // advance to next block
            if (gzseek(file, next_entry, SEEK_SET) == -1) {
                fprintf(stderr, "error: could not advance %zu bytes in archive file\n", entry->get_size());
                return nullptr;
            }
        }

        return read_block();
#endif // 0
        return nullptr;
    }

    class archive_node *read_block() {
#if 0
        ssize_t bytes_read = gzread(file, buffer, sizeof(buffer));
        if (bytes_read != (ssize_t)sizeof(buffer)) {
            fprintf(stderr, "error: attempt to read %zu bytes from archive file failed\n", sizeof(buffer));
            return nullptr;
        }
        entry = (class archive_node *)buffer;
        if (!entry->is_valid()) {
            return nullptr;
        }
        next_entry = entry->bytes_until_next_block() + gztell(file);
        end_of_file = entry->get_size() + gztell(file);
        return entry;
#endif // 0
        return nullptr;
    }

    ssize_t getline(std::string &s) {
        (void)s;
#if 0
        s.clear();
        char read_buffer[8192];
        while (true) {

            ssize_t read_len = sizeof(read_buffer);
            if (read_len + gztell(file) > end_of_file) {
                read_len = end_of_file - gztell(file);
            }
            if (read_len == 0) {
                break;  // no more data
            }
            if (gzgets(file, read_buffer, read_len) == NULL) {
                return s.length();     // EOF
            }
            size_t bytes_read = strlen(read_buffer);
            s.append(read_buffer, bytes_read);
            if (bytes_read > 0 && read_buffer[bytes_read-1] == '\n') {
                s.erase(s.length()-1);   // strip terminating newline
                break;
            }
        }
        return s.length();
#endif // 0
        return 0;
    }
};


#endif // ARCHIVE_H
