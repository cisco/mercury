// Explicit instantiation of exp_functor for SSE2.  Compiled with -msse2.
// This file compiles as an empty translation unit when HAVE_XSIMD is
// not defined (i.e., xsimd is not installed); that is intentional.
#include "softmax.hpp"
#if defined(HAVE_XSIMD)
template void exp_functor::operator()<xsimd::sse2>(xsimd::sse2, std::vector<double>& process_score,
    const std::vector<bool>& malware,
    const std::vector<attribute_result::bitset>& attr,
    double max_score,
    double& score_sum,
    uint64_t index_max,
    double& score_sum_without_max,
    double& malware_prob,
    std::array<double, attribute_result::MAX_TAGS>& attr_prob);
#endif
