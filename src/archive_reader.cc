/*
 * archive_reader.cc
 *
 * driver for compressed tape archive (tar) reader
 */


#include <unistd.h>
#include <filesystem>
#include "libmerc/archive.h"
#include "options.h"

// hex_to_raw() reads a string in hexadecimal, and writes the raw
// octets corresponding to that string to output.  If an error occurs,
// a number less than zero is returned; otherwise, the number of bytes
// written to the output buffer is returned.
//
ssize_t hex_to_raw(const void *output,
                  size_t output_buf_len,
                  const char *null_terminated_hex_string) {
    const char *hex = null_terminated_hex_string;
    const unsigned char *out = (uint8_t *)output;
    size_t count = 0;

    while (output_buf_len-- > 0) {
        if (hex[0] == 0 || hex[0] == '\n') {
            break;
        }
        if (hex[1] == 0) {
            return count;   /* error */
        }
        if (!isxdigit(hex[0]) || !isxdigit(hex[1])) {
            return -1;
        }
        sscanf(hex, "%2hhx", (unsigned char *)&out[count++]);
        hex += 2;
    }
    return count;
}

using namespace mercury_option;

int main(int argc, char *argv[]) {

    const char summary[] =
        "usage:\n"
        "   archive_reader [OPTIONS]\n"
        "\n"
        "OPTIONS\n"
        ;
    class option_processor opt({
        { argument::required,   "--archive",   "read file <archive>" },
        { argument::required,   "--directory", "set the directory to <arg>" },
        { argument::required,   "--decrypt",   "decrypt using key from file <arg>" },
        { argument::none,       "--extract",   "extract archive" },
        { argument::none,       "--list",      "list archive entries" },
        { argument::none,       "--dump",      "dump archive entries" },
        { argument::none,       "--help",      "print out help message" }
    });
    if (!opt.process_argv(argc, argv)) {
        opt.usage(stderr, argv[0], summary);
        return EXIT_FAILURE;
    }

    auto [ archive_is_set, archive ] = opt.get_value("--archive");
    auto [ dir_is_set, directory ] = opt.get_value("--directory");
    auto [ key_is_set, key_str ] = opt.get_value("--decrypt");
    bool list       = opt.is_set("--list");
    bool dump       = opt.is_set("--dump");
    bool extract    = opt.is_set("--extract");
    bool print_help = opt.is_set("--help");

    if (!archive_is_set) {
        fprintf(stderr, "error: no archive specified on command line\n");
        opt.usage(stdout, argv[0], summary);
        return EXIT_FAILURE;
    }

    if (!list && !dump && !extract && !print_help) {
        fprintf(stderr, "warning: no actions specified on command line\n");
    }

    if (print_help) {
        opt.usage(stdout, argv[0], summary);
        return EXIT_SUCCESS;
    }

    if (dir_is_set) {
        if (chdir(directory.c_str()) < 0) {
            fprintf(stderr, "error: could not set directory to %s\n", directory.c_str());
            return EXIT_FAILURE;
        }
    }

    // set the key k to that provided in the file specified in the
    // --decrypt option, if present, or to nullptr otherwise
    //
    uint8_t *k = nullptr;
    unsigned char key[16] = { 0x00, };
    if (key_is_set) {
        FILE *keyfile = fopen(key_str.c_str(), "r");
        if (keyfile == nullptr) {
            fprintf(stderr, "error: could not open key file %s\n", key_str.c_str());
            return EXIT_FAILURE;
        }
        char raw_key[32];
        size_t bytes_read = fread(raw_key, sizeof(char), sizeof(raw_key), keyfile);
        if (bytes_read != sizeof(raw_key)) {
            fprintf(stderr, "error: could not read key from file %s (got %zu)\n", key_str.c_str(), bytes_read);
            return EXIT_FAILURE;
        }
        ssize_t raw_bytes = hex_to_raw(key, sizeof(key), raw_key);
        if (raw_bytes != 16) {
            fprintf(stderr, "error: could not convert input string into raw key (expected 32 hex chars)\n");
            opt.usage(stderr, argv[0], summary);
            return EXIT_FAILURE;
        }
        k = key;
    }

    const char *archive_file_name = archive.c_str();
    class encrypted_compressed_archive tar{archive_file_name, k};
    const class archive_node *entry = tar.get_next_entry();
    if (entry == nullptr) {
        fprintf(stderr, "error: could not read any entries from archive file %s\n", archive_file_name);
    }

    if (list | dump) {
        // print out [summary of] each archive entry
        while (entry != nullptr) {

            // report on entry
            entry->print(stderr);
            if (entry->is_directory()) {
                fprintf(stderr, "type: directory\n");

            } else if (entry->is_regular_file()) {
                fprintf(stderr, "type: regular file\n");

                if (dump) {
                    // write out file, one line at a time
                    std::string line;
                    while (tar.getline(line)) {
                        fprintf(stdout, "%s\n", line.c_str());
                    }
                }

            } else {
                fprintf(stderr, "type: unsupported\n");
            }

            // advance to next entry
            entry = tar.get_next_entry();
        }
    }

    if (extract) {
        while (entry != nullptr) {

            if (entry->is_directory()) {

                // create directory, if need be
                std::string name = entry->get_name();
                if (name != "./") {
                    std::error_code e;
                    if (std::filesystem::create_directory(name, e) == false) {
                        fprintf(stderr, "error: could not create directory %s\n", name.c_str());
                        return EXIT_FAILURE;
                    }
                }

            } else if (entry->is_regular_file()) {

                // create file
                std::string name = entry->get_name();
                std::ofstream file{name};
                if (!file) {
                    fprintf(stderr, "error: could not create file %s\n", name.c_str());
                    return EXIT_FAILURE;
                }
                // write out file, one line at a time
                std::string line;
                while (tar.getline(line)) {
                    file << line.c_str() << '\n';
                }

            } else {
                fprintf(stderr, "error: unsupported archive entry type (flag: %u)\n", entry->get_type_flag());
                return EXIT_FAILURE;
            }

            // advance to next entry
            entry = tar.get_next_entry();
        }
    }

    return EXIT_SUCCESS;
}
