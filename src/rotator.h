// rotator.h
//
// file name rotation

#ifndef ROTATOR_H
#define ROTATOR_H

#include <string>

class rotator {
public:

    rotator(const char *filename,
            const char *filename_extension=nullptr) :
        file_number{0},
        base_name{filename},
        extension{filename_extension},
        file_name{filename}
    {
        file_name.append(extension);
    }

    const char *get_next_name() {
        /*
         * create filename that includes sequence number and date/timestamp
         */
        file_name = base_name;

        char file_num[MAX_HEX];
        snprintf(file_num, MAX_HEX, "%x", file_number++);
        file_name.append("-").append(file_num);

        char time_str[128];
        struct timeval now;
        gettimeofday(&now, NULL);
        strftime(time_str, sizeof(time_str) - 1, "%Y-%m-%d-%H-%M-%S", localtime(&now.tv_sec));
        file_name.append("-").append(time_str);

        file_name.append(extension);

        return file_name.c_str();
    }

    const char *get_current_name() const {
        return file_name.c_str();
    }

private:
    unsigned int file_number;
    std::string base_name;   // prefix common to all files
    std::string extension;   // extension, if any
    std::string file_name;   // name of current file

};

#endif // ROTATOR_H
