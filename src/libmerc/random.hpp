///
/// \file random.hpp
///
/// \brief Operating-system random byte generation.
///
/// \details
/// This header exposes the small random-byte interface used by components that
/// need process-local secret material.  The primary API, \ref
/// os_random::fill_bytes, asks the operating-system CSPRNG for bytes and
/// returns whether that request succeeded.  Callers that need to make their own
/// policy decision should use that API and check the `[[nodiscard]]` result.
///
/// The secondary API, \ref os_random::fill_bytes_with_fallback, is for startup
/// paths where refusing to initialize is worse than using weak process-local
/// entropy.  It first calls \ref os_random::fill_bytes.  On failure it derives
/// bytes from clocks, process-local addresses, a monotonic counter, and cheap
/// process/thread identifiers where available.  That fallback is not a CSPRNG
/// and must not be used for cryptographic keys.  Its purpose is only to avoid a
/// fixed public value when OS entropy is unexpectedly unavailable.
///
/// Copyright (c) 2026 Cisco Systems, Inc. All rights reserved.
/// License: see the repository LICENSE file.
///

#ifndef RANDOM_HPP
#define RANDOM_HPP

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <thread>

#if defined(_WIN32)
#include <process.h>
#if defined(_MSC_VER)
#pragma comment(lib, "bcrypt.lib")
#endif
#if defined(_MSC_VER) || defined(__MINGW32__) || defined(__MINGW64__)
#define OS_RANDOM_BCRYPT_IMPORT __declspec(dllimport)
#define OS_RANDOM_BCRYPT_CALL __stdcall
#else
#define OS_RANDOM_BCRYPT_IMPORT
#define OS_RANDOM_BCRYPT_CALL
#endif
extern "C" OS_RANDOM_BCRYPT_IMPORT long OS_RANDOM_BCRYPT_CALL
BCryptGenRandom(void *algorithm, unsigned char *buffer, unsigned long length, unsigned long flags);
#undef OS_RANDOM_BCRYPT_IMPORT
#undef OS_RANDOM_BCRYPT_CALL
#elif defined(__linux__)
#include <cerrno>
#include <sys/syscall.h>
#include <unistd.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <cstdlib>
#include <unistd.h>
#endif

namespace os_random {

/// \namespace os_random
/// \brief Portable random-byte helpers backed by operating-system entropy.
///
/// \details
/// The namespace intentionally exposes bytes rather than a PRNG object.  Normal
/// callers should treat a false return from \ref fill_bytes as a hard failure or
/// choose an explicit fallback policy.

namespace detail {

#if defined(_WIN32)
static constexpr unsigned long bcrypt_use_system_preferred_rng = 0x00000002UL;
#endif

/// \brief Avalanche a 64-bit value.
///
/// \details
/// This non-cryptographic mixer is used only by the weak fallback path to
/// diffuse low-quality process-local values into output bytes.  It is not used
/// when the operating-system CSPRNG succeeds.
///
/// \param value The value to mix.
/// \return A deterministically mixed 64-bit value.
///
inline uint64_t mix64(uint64_t value) noexcept {
    value ^= value >> 30;
    value *= 0xbf58476d1ce4e5b9ULL;
    value ^= value >> 27;
    value *= 0x94d049bb133111ebULL;
    value ^= value >> 31;
    return value;
}

/// \brief Combine one value into a weak fallback state.
///
/// \param state The fallback state to update.
/// \param value The value to mix into \p state.
///
inline void mix_into(uint64_t &state, uint64_t value) noexcept {
    state = mix64(state ^ value);
}

/// \brief Collect weak process-local fallback entropy.
///
/// \details
/// The result is intended only for \ref weak_fill_bytes.  Pointer-to-integer
/// conversions are implementation-defined, but that is acceptable here because
/// the values are used only as best-effort process-local variation.  Address
/// space layout randomization, clocks, and the counter help avoid reusing the
/// same fallback stream across processes and calls.
///
/// \param buffer The caller's output buffer; its address is mixed into the seed.
/// \param length The requested output length; mixed into the seed.
/// \return A weak, process-local seed.
///
inline uint64_t weak_entropy_seed(const void *buffer, size_t length) noexcept {
    uint64_t local = 0;
    static uint64_t static_local = 0;
    static std::atomic<uint64_t> counter{0};

    uint64_t seed = 0x6a09e667f3bcc909ULL;
    mix_into(seed, static_cast<uint64_t>(
        std::chrono::high_resolution_clock::now().time_since_epoch().count()));
    mix_into(seed, static_cast<uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count()));
    mix_into(seed, static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&local)));
    mix_into(seed, static_cast<uint64_t>(reinterpret_cast<uintptr_t>(&static_local)));
    mix_into(seed, static_cast<uint64_t>(reinterpret_cast<uintptr_t>(buffer)));
    mix_into(seed, static_cast<uint64_t>(length));
    mix_into(seed, counter.fetch_add(1, std::memory_order_relaxed));
    mix_into(seed, static_cast<uint64_t>(
        std::hash<std::thread::id>{}(std::this_thread::get_id())));

#if defined(_WIN32)
    mix_into(seed, static_cast<uint64_t>(_getpid()));
#elif defined(__linux__) && defined(SYS_gettid)
    mix_into(seed, static_cast<uint64_t>(getpid()));
    mix_into(seed, static_cast<uint64_t>(syscall(SYS_gettid)));
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    mix_into(seed, static_cast<uint64_t>(getpid()));
#endif

    return seed;
}

/// \brief Fill bytes from the weak fallback generator.
///
/// \details
/// This function is deterministic once seeded by \ref weak_entropy_seed.  It is
/// not suitable for cryptographic key generation.  It is adequate only as a
/// last-resort source of non-fixed process-local bytes for randomized data
/// structures.
///
/// \param buffer The buffer to fill.
/// \param length The number of bytes to write.
///
inline void weak_fill_bytes(void *buffer, size_t length) noexcept {
    auto *out = static_cast<unsigned char *>(buffer);
    uint64_t state = weak_entropy_seed(buffer, length);

    while (length != 0) {
        state += 0x9e3779b97f4a7c15ULL;
        const uint64_t block = mix64(state);
        const size_t chunk = length < sizeof(block) ? length : sizeof(block);
        for (size_t i = 0; i < chunk; i++) {
            out[i] = static_cast<unsigned char>(block >> (i * 8));
        }
        out += chunk;
        length -= chunk;
    }
}

} // namespace detail

/// \brief Fill a buffer with bytes from the operating-system CSPRNG.
///
/// This function does not provide a deterministic fallback. Callers that need
/// secret key material must treat a false return value as a hard failure.
///
/// \param buffer The buffer to fill.
/// \param length The number of bytes to write.
/// \return True if and only if all requested bytes were written.
///
[[nodiscard]] inline bool fill_bytes(void *buffer, size_t length) noexcept {
#if defined(_WIN32)
    auto *out = static_cast<unsigned char *>(buffer);
    while (length != 0) {
        const size_t chunk = length > std::numeric_limits<unsigned long>::max()
            ? std::numeric_limits<unsigned long>::max()
            : length;
        const long result = BCryptGenRandom(nullptr,
                                            out,
                                            static_cast<unsigned long>(chunk),
                                            detail::bcrypt_use_system_preferred_rng);
        if (result != 0) {
            return false;
        }
        out += chunk;
        length -= chunk;
    }
    return true;
#elif defined(__linux__) && defined(SYS_getrandom)
    auto *out = static_cast<unsigned char *>(buffer);
    while (length != 0) {
        const long result = syscall(SYS_getrandom, out, length, 0);
        if (result > 0) {
            const size_t byte_count = static_cast<size_t>(result);
            out += byte_count;
            length -= byte_count;
        } else if (result == -1 && errno == EINTR) {
            continue;
        } else {
            return false;
        }
    }
    return true;
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    arc4random_buf(buffer, length);
    return true;
#else
    (void)buffer;
    (void)length;
    return false;
#endif
}

/// \brief Fill a buffer with OS-random bytes, using weak fallback entropy if needed.
///
/// Prefer \ref fill_bytes when failure must be visible to the caller. This
/// helper exists for startup paths where a weak process-local key is preferable
/// to refusing to initialize. The fallback is not a CSPRNG and should not be
/// used for cryptographic key material.
///
/// \param buffer The buffer to fill.
/// \param length The number of bytes to write.
///
inline void fill_bytes_with_fallback(void *buffer, size_t length) noexcept {
    if (fill_bytes(buffer, length)) {
        return;
    }
    detail::weak_fill_bytes(buffer, length);
}

} // namespace os_random

#endif // RANDOM_HPP
