/*
 * version.h
 *
 * a class for handling semantic versioning
 *
 * Copyright (c) 2020 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef SEMANTIC_VERSION_H
#define SEMANTIC_VERSION_H

#include <stdint.h>
#include <stdio.h>

struct semantic_version {
    unsigned int major;
    unsigned int minor;
    unsigned int patchlevel;

    semantic_version(uint8_t maj, uint8_t min, uint8_t patch) {
        major = maj;
        minor = min;
        patchlevel = patch;
    }
    explicit semantic_version(const char *version_string) {
        sscanf(version_string, "%u.%u.%u", &major, &minor, &patchlevel);
    }

    void print(FILE *f) const {
        fprintf(f, "%u.%u.%u\n", major, minor, patchlevel);
    }
    bool is_less_than(struct semantic_version v) const {
        if (major < v.major || minor < v.minor || patchlevel < v.patchlevel) {
            return true;
        }
        return false;
    }
    uint32_t get_version_as_uint32() const {
        return (uint32_t)major << 24 | (uint32_t)minor << 16 | (uint32_t)patchlevel << 8 | 0;
    }
};

#endif /* SEMANTIC_VERSION_H */
