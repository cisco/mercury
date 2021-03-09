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
            fprintf(stderr, "error: could not open file %s\n", filename);
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
                fprintf(stderr, "error: could not read %zu bytes from file\n", entry->get_size());
                return nullptr;
            }
        }

        size_t bytes_read = fread(buffer, 1, sizeof(buffer), file);
        if (bytes_read != sizeof(buffer)) {
            fprintf(stderr, "error: could not read %zu bytes from file\n", sizeof(buffer));
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
            fprintf(stderr, "error: could not open file %s\n", filename);
        }
        // note: file may be nullptr after construction
    }

    class archive_node *get_next_entry() {

        if (file == nullptr) {
            return nullptr;   // error; not reading a compressed archive file
        }

        if (entry != nullptr) {

            // advance to next block
            if (gzseek(file, next_entry, SEEK_SET) == -1) {
                fprintf(stderr, "error: could not read %zu bytes from file\n", entry->get_size());
                return nullptr;
            }
        }

        return read_block();
    }

    class archive_node *read_block() {
        ssize_t bytes_read = gzread(file, buffer, sizeof(buffer));
        if (bytes_read != (ssize_t)sizeof(buffer)) {
            fprintf(stderr, "error: could not read %zu bytes from file\n", sizeof(buffer));
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

            //fprintf(stdout, "tell: %zu\n", gztell(file));
            ssize_t read_len = sizeof(read_buffer);
            if (read_len + gztell(file) > end_of_file) {
                read_len = end_of_file - gztell(file);
            }
            if (read_len == 0) {
                break;  // no more data
            }
            //fprintf(stdout, "reading %zd bytes\n", read_len);
            if (gzgets(file, read_buffer, read_len) == NULL) {
                //fprintf(stdout, "got EOF\n");
                return s.length();     // EOF
            }
            unsigned bytes_read = strlen(read_buffer);
            //fprintf(stdout, "got %u bytes\n", bytes_read);
            s.append(read_buffer, bytes_read);
            if (read_buffer[bytes_read-1] == '\n') {
                s.back() = '\0';
                break;
            }
        }
        return s.length();
    }

};


#endif // ARCHIVE_H
