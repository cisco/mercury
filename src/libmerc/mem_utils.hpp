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
    using fixed_storage = typename std::aligned_storage<sizeof(T), alignof(T)>::type;
    fixed_storage *mem_pool = nullptr;
    size_t cur_element;
    bool reallocate = false;

public:
    using value_type = T;

    fixed_fifo_allocator() noexcept : cur_element{0} {
        mem_pool = new fixed_storage[N];
    }


    template <typename U>
    fixed_fifo_allocator(const fixed_fifo_allocator<U, N>&) noexcept : cur_element{0} {
        mem_pool = new fixed_storage[N];
    }


    fixed_fifo_allocator(fixed_fifo_allocator&& other) noexcept {
        cur_element = other.cur_element;
        mem_pool = other.mem_pool;
        reallocate = other.reallocate;

        if (this != &other) {
            other.mem_pool = nullptr;
        }
    }


    ~fixed_fifo_allocator() {
        if (mem_pool != nullptr) {
            delete[] reinterpret_cast<fixed_storage *>(mem_pool);
        }
    }


    T* allocate(size_t n) {
        if (n != 1) { // allocate bucket data
            if (reallocate) {
                throw std::bad_alloc();
            }
            if (n > N) {
                delete[] reinterpret_cast<fixed_storage *>(mem_pool);
                mem_pool = new fixed_storage[n];
                reallocate = true;
            }

            return reinterpret_cast<T*>(mem_pool);
        }

        if (cur_element >= N) {
            cur_element = cur_element % N;
        }
        return reinterpret_cast<T*>(&mem_pool[cur_element++]);
    }


    void deallocate(T*, size_t) noexcept {
        // no need to deallocate
        return ;
    }


    template <typename U>
    struct rebind {
        using other = fixed_fifo_allocator<U, N>;
    };


    // Comparison operators
    bool operator==(const fixed_fifo_allocator&) const noexcept { return false; }
    bool operator!=(const fixed_fifo_allocator&) const noexcept { return true; }


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

        // Allocate all slots
        for (std::size_t i = 0; i < M; ++i) {
            alloc.deallocate(ptrs[i], 1);
            ptrs[i] = alloc.allocate(1);
            new (ptrs[i]) Dummy(static_cast<int>(i));
            if (ptrs[i]->x != static_cast<int>(i)) {
                return false;
            }
        }

        // Deallocate all
        for (std::size_t i = 0; i < M; ++i) {
            alloc.deallocate(ptrs[i], 1);
        }

        // Test rebind
        fixed_fifo_allocator<int, 4> int_alloc;
        using char_alloc_type = fixed_fifo_allocator<int, 4>::rebind<char>::other;
        char_alloc_type char_alloc;

        char* char_ptr = char_alloc.allocate(1);
        if (char_ptr == nullptr) {
            return false;
        }
        *char_ptr = 'A';
        if (*char_ptr != 'A') {
            return false;
        }
        char_alloc.deallocate(char_ptr, 1);

        // Test comparison operators
        fixed_fifo_allocator<Dummy, M> alloc2;
        if (alloc == alloc2) { // we don't want alloc2 to release alloc memory
            return false;
        }

        // All tests pass
        return true;
    }

#endif // NDEBUG

};


#endif // MEM_UTILS_HPP
