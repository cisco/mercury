#ifndef SOFTMAX_HPP
#define SOFTMAX_HPP
#include "result.h"
#include <cmath>
#include <type_traits>

// HAVE_XSIMD (set by configure) indicates the xsimd library
// is installed and its headers are available.  This is a pure
// build-time library-presence check.
//
// HAVE_XSIMD_DISPATCH (set below) additionally requires that we are
// compiling for a CPU architecture family for which xsimd provides
// SIMD dispatch targets (currently x86, x86-64, and AArch64).  The
// library could be present on an unsupported architecture (e.g.
// RISC-V, s390x, MIPS) where no dispatch targets exist; in that
// case HAVE_XSIMD is defined but HAVE_XSIMD_DISPATCH is not, and
// the scalar fallback is used.
//
// Neither macro checks whether the *running* CPU actually supports a
// particular SIMD instruction set (e.g. AVX2 vs. SSE2).  That is a
// runtime decision made by check_simd() / xsimd::available_architectures().
//
#if defined(HAVE_XSIMD)
#include "xsimd/xsimd.hpp"

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86) || defined(__aarch64__) || defined(_M_ARM64)
#define HAVE_XSIMD_DISPATCH 1
#endif

struct exp_functor {
    template <class Arch>
    void operator()(Arch, std::vector<double>& process_score,
    const std::vector<bool>& malware,
    const std::vector<attribute_result::bitset>& attr,
    double max_score,
    double& score_sum,
    uint64_t index_max,
    double& score_sum_without_max,
    double& malware_prob,
    std::array<double, attribute_result::MAX_TAGS>& attr_prob);

    template <class Arch>
    void operator()(Arch) {
        printf_err(log_debug, "Using SIMD Architecture %s\n", Arch::name());
    }
};

template <class Arch>
void exp_functor::operator()(Arch, std::vector<double>& process_score,
    const std::vector<bool>& malware,
    const std::vector<attribute_result::bitset>& attr,
    double max_score,
    double& score_sum,
    uint64_t index_max,
    double& score_sum_without_max,
    double& malware_prob,
    std::array<double, attribute_result::MAX_TAGS>& attr_prob) {

    using batch = xsimd::batch<float, Arch>;
    size_t i = 0;
    size_t simd_size = batch::size;

    // SIMD processing for process_score
    for (; i + simd_size <= process_score.size(); i += simd_size) {
        batch ps_batch = batch::load_unaligned(&process_score[i]);
        ps_batch = xsimd::exp(ps_batch - batch(max_score));

        ps_batch.store_unaligned(&process_score[i]);
        score_sum += xsimd::reduce_add(ps_batch);

        for (std::size_t j = 0; j < simd_size; ++j) {
            auto val = ps_batch.get(j);
            if (i + j != index_max) {
                score_sum_without_max += val;
            }
            if (malware[i + j]) {
                malware_prob += val;
            }
            for (int k = 0; k < attribute_result::MAX_TAGS; ++k) {
                if (attr[i + j][k]) {
                    attr_prob[k] += val;
                }
            }
        }
    }

    // Process remaining elements
    for (; i < process_score.size(); ++i) {
        process_score[i] = expf((float)(process_score[i] - max_score));
        score_sum += process_score[i];
        if (i != index_max) {
            score_sum_without_max += process_score[i];
        }
        if (malware[i]) {
            malware_prob += process_score[i];
        }
        for (int j = 0; j < attribute_result::MAX_TAGS; j++) {
            if (attr[i][j]) {
                attr_prob[j] += process_score[i];
            }
        }
    }
}

#if defined(HAVE_XSIMD_DISPATCH) && (defined(__i386__) || defined(__x86_64__))
extern template void exp_functor::operator()<xsimd::avx2>(xsimd::avx2, std::vector<double>& process_score,
    const std::vector<bool>& malware,
    const std::vector<attribute_result::bitset>& attr,
    double max_score,
    double& score_sum,
    uint64_t index_max,
    double& score_sum_without_max,
    double& malware_prob,
    std::array<double, attribute_result::MAX_TAGS>& attr_prob);

extern template void exp_functor::operator()<xsimd::avx>(xsimd::avx, std::vector<double>& process_score,
    const std::vector<bool>& malware,
    const std::vector<attribute_result::bitset>& attr,
    double max_score,
    double& score_sum,
    uint64_t index_max,
    double& score_sum_without_max,
    double& malware_prob,
    std::array<double, attribute_result::MAX_TAGS>& attr_prob);

extern template void exp_functor::operator()<xsimd::sse2>(xsimd::sse2, std::vector<double>& process_score,
    const std::vector<bool>& malware,
    const std::vector<attribute_result::bitset>& attr,
    double max_score,
    double& score_sum,
    uint64_t index_max,
    double& score_sum_without_max,
    double& malware_prob,
    std::array<double, attribute_result::MAX_TAGS>& attr_prob);
#elif defined(HAVE_XSIMD_DISPATCH) && defined(__aarch64__)
extern template void exp_functor::operator()<xsimd::neon64>(xsimd::neon64, std::vector<double>& process_score,
    const std::vector<bool>& malware,
    const std::vector<attribute_result::bitset>& attr,
    double max_score,
    double& score_sum,
    uint64_t index_max,
    double& score_sum_without_max,
    double& malware_prob,
    std::array<double, attribute_result::MAX_TAGS>& attr_prob);
#endif

// Create the dispatching function, specifying the architectures we want to target.
#if defined(HAVE_XSIMD_DISPATCH) && (defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86))
#ifdef _WIN32
using simd_arch_list = xsimd::arch_list<xsimd::sse2>;
#else
using simd_arch_list = xsimd::arch_list<xsimd::avx2, xsimd::avx, xsimd::sse2>;
#endif
#elif defined(HAVE_XSIMD_DISPATCH) && (defined(__aarch64__) || defined(_M_ARM64))
using simd_arch_list = xsimd::arch_list<xsimd::neon64>;
#endif

#if defined(HAVE_XSIMD_DISPATCH)
static inline xsimd::detail::dispatcher<exp_functor, simd_arch_list>& get_dispatched() {
    static xsimd::detail::dispatcher<exp_functor, simd_arch_list> dispatched =
        xsimd::dispatch<simd_arch_list>(exp_functor{});
    return dispatched;
}

static inline bool check_simd() {
    // Static variable to store the result of the SIMD check
    static bool is_simd_available = []() -> bool {
        auto archs = xsimd::available_architectures();
        if (archs.sse2 || archs.neon64) {
            auto dispatched = get_dispatched();
            dispatched();
            return true;
        }
        return false;
    }();

    return is_simd_available;
}

/// Dispatch SIMD-accelerated softmax.  Only valid when check_simd() is true.
/// Currently only supports double.  To add float support: add float
/// overloads to exp_functor, extern template declarations per arch,
/// and explicit instantiations in the corresponding .cc files.
template <typename floating_point_type, size_t MAX_TAGS>
static inline void dispatch_simd_softmax(
    std::vector<floating_point_type>& process_score,
    std::vector<bool>& malware,
    std::vector<attribute_result::bitset>& attr,
    floating_point_type& max_score,
    floating_point_type& score_sum,
    uint64_t& index_max,
    floating_point_type& score_sum_without_max,
    floating_point_type& malware_prob,
    std::array<floating_point_type, MAX_TAGS>& attr_prob)
{
    static_assert(std::is_same_v<floating_point_type, double>,
                  "SIMD softmax currently only supports double");
    get_dispatched()(process_score, malware, attr, max_score, score_sum,
                    index_max, score_sum_without_max, malware_prob, attr_prob);
}

#endif // HAVE_XSIMD_DISPATCH

#endif // HAVE_XSIMD

// When xsimd is absent or the platform has no dispatch backend,
// provide fallbacks so callers compile unconditionally.
#if !defined(HAVE_XSIMD) || !defined(HAVE_XSIMD_DISPATCH)
static inline bool check_simd() { return false; }

template <typename floating_point_type, size_t MAX_TAGS>
static inline void dispatch_simd_softmax(
    std::vector<floating_point_type>&,
    std::vector<bool>&,
    std::vector<attribute_result::bitset>&,
    floating_point_type&,
    floating_point_type&,
    uint64_t&,
    floating_point_type&,
    floating_point_type&,
    std::array<floating_point_type, MAX_TAGS>&)
{ }
#endif

template <typename floating_point_type, size_t MAX_TAGS>
inline void softmax(std::vector<floating_point_type> &process_score,
                    std::vector<bool> &malware,
                    std::vector<attribute_result::bitset> &attr,
                    floating_point_type &max_score,
                    floating_point_type &score_sum,
                    uint64_t &index_max,
                    floating_point_type &score_sum_without_max,
                    floating_point_type &malware_prob,
                    std::array<floating_point_type, MAX_TAGS> &attr_prob
                    )
{
        if (check_simd()) {
            dispatch_simd_softmax<floating_point_type, MAX_TAGS>(
                process_score, malware, attr, max_score, score_sum,
                index_max, score_sum_without_max, malware_prob, attr_prob);
            return;
        }

        //
        // No SIMD instruction set is available, so compute softmax with standard C++
        //
        for (uint64_t i = 0; i < process_score.size(); ++i) {
            process_score[i] = expf((float)(process_score[i] - max_score));
            score_sum += process_score[i];
            if (i != index_max) {
                score_sum_without_max += process_score[i];
            }
            if (malware[i]) {
                malware_prob += process_score[i];
            }
            for (int j = 0; j < attribute_result::MAX_TAGS; j++) {
                if (attr[i][j]) {
                    attr_prob[j] += process_score[i];
                }
            }
        }
}

#endif // SOFTMAX_HPP
