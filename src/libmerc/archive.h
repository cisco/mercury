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

    encrypted_compressed_archive(const char *filename) : entry{nullptr}, next_entry{0}, end_of_file{0}, fd{0} {
        fd = open(filename, O_RDONLY, "r");
        if (fd == 0) {
            fprintf(stderr, "error: could not open archive file %s\n", filename);
            return;  // error; not reading a compressed archive file
        }
        //file = gzdopen(fd, "r");

        ssize_t file_buffer_bytes = read(fd, file_buffer, sizeof(file_buffer));
        if (file_buffer_bytes < (ssize_t)sizeof(file_buffer)) {
            fprintf(stderr, "error: could not read archive file %s\n", filename);
            return;  // error; not reading a compressed archive file
        }

        //  set next_in, avail_in, zalloc, zfree and opaque
        z.next_in = file_buffer;
        z.avail_in = file_buffer_bytes;
        z.zalloc = _zalloc;
        z.zfree = _zfree;
        z.opaque = nullptr; // ???
        z.next_out = buffer;
        z.avail_out = sizeof(buffer);

        inflateInit(&z);
        int err = inflate(&z, Z_NO_FLUSH);
        // if (err == Z_STREAM_END) {
        //     break;
        // }

        fprintf(stderr, "file_buffer: '%.*s'\n", (int)sizeof(file_buffer), file_buffer);
        fprintf(stderr, "buffer:      '%.*s'\n", (int)sizeof(buffer), buffer);

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
    }

    ssize_t getline(std::string &s) {
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
    }
};


#endif // ARCHIVE_H
