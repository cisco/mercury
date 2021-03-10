/*
 * archive_reader.cc
 *
 * driver for compressed tape archive (tar) reader
 */


#include <unistd.h>
#include <filesystem>
#include "libmerc/archive.h"
#include "options.h"

int main(int argc, char *argv[]) {

    const char summary[] =
        "usage:\n"
        "   archive_reader <archive> [OPTIONS]\n"
        "\n"
        "OPTIONS\n"
        ;
    class option_processor opt({
        { argument::positional, "archive",     "read file <archive>" },
        { argument::required,   "--directory", "set the directory to <arg>" },
        { argument::none,       "--extract",   "extract archive" },
        { argument::none,       "--list",      "list archive entries" },
        { argument::none,       "--dump",      "dump archive entries" },
        { argument::none,       "--help",      "print out help message" }
    });
    if (!opt.process_argv(argc, argv)) {
        opt.usage(stderr, argv[0], summary);
        return EXIT_FAILURE;
    }

    auto [ archive_is_set, archive ] = opt.get_value("archive");
    auto [ dir_is_set, directory ] = opt.get_value("--directory");
    bool list       = opt.is_set("--list");
    bool dump       = opt.is_set("--dump");
    bool extract    = opt.is_set("--extract");
    bool print_help = opt.is_set("--help");

    if (print_help) {
        opt.usage(stdout, argv[0], summary);
        return 0;
    }

    if (dir_is_set) {
        if (chdir(directory.c_str()) < 0) {
            fprintf(stderr, "error: could not set directory to %s\n", directory.c_str());
            return EXIT_FAILURE;
        }
    }

    const char *archive_file_name = archive.c_str();
    class compressed_archive tar{archive_file_name};
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
