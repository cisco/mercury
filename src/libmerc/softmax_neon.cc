#include "softmax.hpp"
template void exp_functor::operator()<xsimd::neon64>(xsimd::neon64, std::vector<double>& process_score,
    const std::vector<bool>& malware,
    const std::vector<attribute_result::bitset>& attr,
    double max_score,
    double& score_sum,
    uint64_t index_max,
    double& score_sum_without_max,
    double& malware_prob,
    std::array<double, attribute_result::MAX_TAGS>& attr_prob);
