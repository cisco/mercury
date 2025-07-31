// static_dict.hpp
//
// a constexpr static string-to-integer dictionary

#ifndef STATIC_DICT_HPP
#define STATIC_DICT_HPP

#include <iterator>   // for std::distance()
#include <array>

static constexpr bool streq(const char *l, const char *r) {
    while (*l and *r) {
        if (*l != *r) {
            return false;
        }
        ++l;
        ++r;
    }
    return *l == '\0' and *r == '\0';
}

template <size_t N>
class static_dictionary {
    const std::array<const char *, N> a;

public:

    constexpr static_dictionary(const std::array<const char *, N> &m) : a{m} { }

    constexpr size_t index(const char *s) const {
        for (auto x = a.begin(); x < a.end(); x++) {
            if (streq(*x, s)) {
                return std::distance(a.begin(), x);
            }
        }
        return 0;
    }

    constexpr const char *value(size_t idx) const {
        return a[idx];
    }

    static bool unit_test(FILE *f=nullptr) {

        constexpr static_dictionary<4> dogs{
            {
                "unknown",
                "Westie",
                "Yorkshire Terrier",
                "Pug"
            }
        };

        const auto test = [&dogs, &f](const char *s, size_t idx) {
            if (dogs.index(s) != idx) {
                if (f) {
                    fprintf(f, "error in test case %s: expected %zu, got %zu\n", s, idx, dogs.index(s));
                }
                return false;
            }
            if (dogs.value(idx) != s and idx != 0) {
                if (f) {
                    fprintf(f, "error in test case %zu: expected %s, got %s\n", idx, s, dogs.value(idx));
                }
                return false;
            }
            return true;
        };

        return test("unknown", 0)
            and test("Westie", 1)
            and test("Yorkshire Terrier", 2)
            and test("Pug", 3)
            and test("Siamese", 0)
            and test("Westi", 0)
            and test("Westie!", 0);
    }

};

#endif // static_dict.hpp
