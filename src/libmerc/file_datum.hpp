// file_datum.hpp

#ifndef FILE_DATUM_HPP
#define FILE_DATUM_HPP

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

// USE_MMAP causes file reading to use mmap for improved performance;
// you should use it when it is available (Linux).
//
#ifdef USE_MMAP
#include <sys/mman.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "datum.h"


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
            throw std::system_error(errno, std::generic_category(), fname);
        }
        struct stat statbuf;
        if (fstat(fd, &statbuf) != 0) {
            throw std::system_error(errno, std::generic_category(), fname);
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
	    throw std::system_error(errno, std::generic_category());
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
            throw std::system_error(errno, std::generic_category());
        }
	data = buf;
        size_t bytes_read = 0;
        while (bytes_read < file_length) {
            ssize_t result = read(fd, buf, file_length - bytes_read);
            if (result == -1) {
	      throw std::system_error(errno, std::generic_category());
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

#endif // FILE_DATUM_HPP
