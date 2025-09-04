// mem_utils.hpp
//
// helper classes for memory management
//
// Copyright (c) 2025 Cisco Systems, Inc. All rights reserved.
// License at https://github.com/cisco/mercury/blob/master/LICENSE
//

#ifndef MEM_UTILS_HPP
#define MEM_UTILS_HPP


#include <cstddef>
#include <memory>
#include <type_traits>
#include <stdexcept>


// fixed_fifo_allocator is a custom memory allocator intended to be
//   used by an unordered_map. It has two important properties:
//     1. inserts/deletes do not invoke memory allocations/deallocations
//     2. elements are removed on a first-in/first-out basis
//   This allocator is not a general purpose allocator and should be
//   used with caution when the FIFO property holds for your use case.
//
template <typename T, size_t N>
class fixed_fifo_allocator {
    typename std::aligned_storage<sizeof(T), alignof(T)>::type mem_pool[N];
    size_t cur_element;

public:
    using value_type = T;

    fixed_fifo_allocator() noexcept : mem_pool{}, cur_element{0} {}

    template <typename U>
    fixed_fifo_allocator(const fixed_fifo_allocator<U, N>&) noexcept : mem_pool{}, cur_element{0} {}

    T* allocate(size_t n) {
        if (n != 1) { // allocate bucket data
            return reinterpret_cast<T*>(new typename std::aligned_storage<sizeof(T), alignof(T)>::type[n]);
        }

        if (cur_element >= N) {
            cur_element = cur_element % N;
        }
        return reinterpret_cast<T*>(&mem_pool[cur_element++]);
    }

    void deallocate(T* p, size_t n) noexcept {
        if (n != 1) { // deallocate bucket data
            delete[] reinterpret_cast<typename std::aligned_storage<sizeof(T), alignof(T)>::type *>(p);
            return;
        }
        // no need to deallocate node data
    }

    template <typename U>
    struct rebind {
        using other = fixed_fifo_allocator<U, N>;
    };

    // Comparison operators
    bool operator==(const fixed_fifo_allocator&) const noexcept { return true; }
    bool operator!=(const fixed_fifo_allocator&) const noexcept { return false; }


#ifndef NDEBUG

    struct Dummy {
        int x;
        Dummy(int v = 0) : x(v) {}
        bool operator==(const Dummy& other) const { return x == other.x; }
    };

    static bool unit_test() {
        constexpr size_t M = 4;
        fixed_fifo_allocator<Dummy, M> alloc;

        // Allocate all slots
        Dummy* ptrs[M];
        for (std::size_t i = 0; i < M; ++i) {
            ptrs[i] = alloc.allocate(1);
            new (ptrs[i]) Dummy(static_cast<int>(i));
            if (ptrs[i]->x != static_cast<int>(i)) {
                return false;
            }
        }

        // Deallocate one and allocate again
        alloc.deallocate(ptrs[0], 1);
        Dummy* p = alloc.allocate(1);
        new (p) Dummy(42);
        if (p->x != 42) {
            return false;
        }

        // Deallocate all
        for (std::size_t i = 0; i < M; ++i) {
            alloc.deallocate(ptrs[i], 1);
        }
        alloc.deallocate(p, 1); // safe to call even if already deallocated

        // Test rebind
        fixed_fifo_allocator<int, M> alloc2;
        int* iptr = alloc2.allocate(1);
        *iptr = 123;
        if (*iptr != 123) {
            return false;
        }
        alloc2.deallocate(iptr, 1);

        // Test comparison operators
        fixed_fifo_allocator<Dummy, M> alloc3;
        if (alloc != alloc3) {
            return false;
        }

        // All tests pass
        return true;
    }

#endif // NDEBUG

};


#endif // MEM_UTILS_HPP
