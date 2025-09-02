/*
 * mem_utils.hpp
 *
 * Copyright (c) 2025 Cisco Systems, Inc. All rights reserved.
 * License at https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef MEM_UTILS_HPP
#define MEM_UTILS_HPP


#pragma once
#include <cstddef>
#include <memory>
#include <type_traits>
#include <stdexcept>

template <typename T, size_t N>
class FixedAllocator {
    typename std::aligned_storage<sizeof(T), alignof(T)>::type pool_[N];
    bool used_[N]{};
    size_t allocated_;

public:
    using value_type = T;

    FixedAllocator() noexcept : pool_{}, used_{}, allocated_{0} {}

    template <typename U>
    FixedAllocator(const FixedAllocator<U, N>&) noexcept {}

    T* allocate(size_t n) {
        if (n != 1 || allocated_ >= N)
            throw std::bad_alloc();
        for (size_t i = 0; i < N; ++i) {
            if (!used_[i]) {
                used_[i] = true;
                ++allocated_;
                return reinterpret_cast<T*>(&pool_[i]);
            }
        }
        throw std::bad_alloc();
    }

    void deallocate(T* p, size_t n) noexcept {
        if (n != 1) return;
        auto idx = reinterpret_cast<char*>(p) - reinterpret_cast<char*>(pool_);
        idx /= sizeof(T);
        if (idx < N && used_[idx]) {
            used_[idx] = false;
            --allocated_;
        }
    }

    template <typename U>
    struct rebind {
        using other = FixedAllocator<U, N>;
    };

    // Comparison operators
    bool operator==(const FixedAllocator&) const noexcept { return true; }
    bool operator!=(const FixedAllocator&) const noexcept { return false; }
};


#endif
