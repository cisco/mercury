// file_set.hpp
//
// classes for managing sets of input/output files


#ifndef FILE_SET_HPP
#define FILE_SET_HPP

#include <filesystem>
#include <algorithm>
#include <cstdio>
#include <optional>

class file_enumerator {
    std::filesystem::path input;
    bool verbose;

public:

    file_enumerator(const char *input_directory,
                    bool output_warnings = false) :
        input{input_directory},
        verbose{output_warnings}
    { }

    std::optional<std::string> get_matching_files(const std::filesystem::directory_entry &dir_entry) {

        // check (lowercase) file extension
        //
        std::string extension = dir_entry.path().extension();
        std::transform(extension.begin(), extension.end(), extension.begin(),
                       [](char c) { return tolower(c); });
        if (extension == ".pcap" || extension == ".pcapng") {
            return dir_entry.path();
        }

        return std::nullopt;   // nothing to return
    }

    std::filesystem::recursive_directory_iterator recursive_dir_it() {
        return std::filesystem::recursive_directory_iterator(input);
    }

};

class file_set {
    std::filesystem::path input;
    std::filesystem::path output;
    bool verbose;

public:

    file_set(std::filesystem::path &input_directory,
             std::filesystem::path &output_directory,
             bool output_warnings = false) :
        input{input_directory},
        output{output_directory},
        verbose{output_warnings}
    { }

    file_set(const char *input_directory,
             const char *output_directory,
             bool output_warnings = false) :
        input{input_directory},
        output{output_directory},
        verbose{output_warnings}
    { }

    struct input_output_files {
        std::string in;
        std::string out;
    };

    std::optional<input_output_files> get_io_pair(const std::filesystem::directory_entry &dir_entry) {

        // check (lowercase) file extension
        //
        std::string extension = dir_entry.path().extension();
        std::transform(extension.begin(), extension.end(), extension.begin(),
                       [](char c) { return tolower(c); });
        if (extension == ".pcap") {

            // create relative path
            //
            std::filesystem::path rel = std::filesystem::relative(dir_entry.path(), input);

            // create subdirectory
            //
            std::filesystem::create_directories(output / rel.parent_path());

            // create output filename
            //
            std::string fname = output / rel.parent_path() / dir_entry.path().stem();
            std::replace(fname.begin(), fname.end(), ' ', '_');
            fname += ".json";

            return input_output_files{ dir_entry.path(), fname };

        } else if (extension == ".pcapng") {
            if (verbose) {
                fprintf(stderr, "warning: found PCAP-NG file %s\n", dir_entry.path().c_str());
            }
        }

        return std::nullopt;   // nothing to return
    }


    std::filesystem::recursive_directory_iterator recursive_dir_it() {
        return std::filesystem::recursive_directory_iterator(input);
    }

};

#endif // FILE_SET_HPP
