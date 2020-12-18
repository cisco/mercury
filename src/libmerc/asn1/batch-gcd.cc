/*
 * batch-gcd.cc
 */


#include <stdint.h>
#include <iostream>
#include <list>

int main(int argc, char *argv[]) {
    using namespace std;
    list<uint64_t> moduli{ 3*5, 5*7, 7*11, 11*13, 13*17, 17*19, 19*23, 23*29 };
    // list<uint64_t> *tmp = &moduli;
    list<list<uint64_t> *> product_tree;

    for (auto it = moduli.begin(); it != moduli.end(); ) {
        uint64_t y = *it++;
        uint64_t z = *it++;
        cout << y << '\t' << z << '\n';
    }

    // create product tree
    list<uint64_t>::iterator product;
    product_tree.push_back(&moduli);
    auto last_level = &moduli;
    while (1) {
        auto tmp = new list<uint64_t>;
        product_tree.push_back(tmp);
        for (auto it = last_level->begin(); it != last_level->end(); ) {
            auto first = it++;
            auto second = it++;
            tmp->push_back(*first * *second);
        }

        bool first = true;
        cout << "[";
        for (auto it = tmp->begin(); it != tmp->end(); ) {
            if (first) {
                first = false;
            } else {
                cout << ',';
            }
            uint64_t y = *it++;
            cout << y;
        }
        cout << "]" << '\n';

        if (tmp->size() == 1) {
            product = tmp->begin();
            break;
        }

        last_level = tmp;
    }

    cout << "product: " << *product << '\n';

    // create remainder tree

    // TBD

    // report on common factors

    // TBD
    
    return 0;
}
