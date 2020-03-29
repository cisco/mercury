/*
 * version.h
 *
 * a class for handling semantic versioning
 */

#ifndef SEMANTIC_VERSION
#define SEMANTIC_VERSION

struct semantic_version {
    unsigned int major;
    unsigned int minor;
    unsigned int patchlevel;

    semantic_version(uint8_t maj, uint8_t min, uint8_t patch) {
        major = maj;
        minor = min;
        patchlevel = patch;
    }
    semantic_version(const char *version_string) {
        sscanf(version_string, "%u.%u.%u", &major, &minor, &patchlevel);
    }
    void print(FILE *f) {
        fprintf(f, "%u.%u.%u\n", major, minor, patchlevel);
    }
    bool is_less_than(struct semantic_version v) {
        if (v.major < major || v.minor < minor || v.patchlevel < patchlevel) {
            return true;
        }
        return false;
    }
};

#endif /* SEMANTIC_VERSION */
