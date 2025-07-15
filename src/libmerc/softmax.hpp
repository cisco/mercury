#ifndef SOFTMAX_HPP
#define SOFTMAX_HPP
#include "result.h"
#include "xsimd/xsimd.hpp"

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

#if defined(__i386__) || defined(__x86_64__)
// Inform the compiler that NEON and AVX2 implementations are to be found in another compilation unit.
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
#elif defined(__aarch64__)
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
#endif
