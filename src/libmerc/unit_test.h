// unit_test.h
//
// simple c++11 header-only unit test support

#ifndef UNIT_TEST_H
#define UNIT_TEST_H

#include <functional>

template <size_t N>
class unit_test {
    std::array<std::function<bool()>, N> &test_funcs;

public:

    unit_test(std::array<std::function<bool()>, N> &tests) : test_funcs{tests} {  }

    bool evaluate() {
        for (const auto & f : test_funcs) {
            if (f() == false) {
                return false;
            }
        }
        return true;
    }

};

#endif // UNIT_TEST_H
