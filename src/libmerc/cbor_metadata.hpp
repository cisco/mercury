// cbor_metadata.hpp
//
// CBOR metadata buffer manager for encoding per-packet feature data.

#ifndef CBOR_METADATA_HPP
#define CBOR_METADATA_HPP

#include "cbor.hpp"

/// Fixed-buffer CBOR writer for per-packet metadata. Manages the raw
/// buffer; the caller is responsible for opening/closing the outer CBOR
/// map via cbor_object.
class cbor_metadata_context {
    static constexpr size_t MAX_CBOR_METADATA_LEN = 4096;

    uint8_t buffer_[MAX_CBOR_METADATA_LEN];
    writeable w_;
    size_t length_ = 0;
    bool truncated_ = false;
    bool feature_written_ = false;

public:
    cbor_metadata_context() : buffer_{}, w_{} {}

    /// Reset buffer for new packet.
    void reset() {
        w_ = writeable{buffer_, buffer_ + MAX_CBOR_METADATA_LEN};
        length_ = 0;
        truncated_ = false;
        feature_written_ = false;
    }

    /// Get writeable for cbor_object to write into.
    writeable& get_writer() { return w_; }

    /// Mark that a feature has been written to the buffer.
    void set_feature_written() { feature_written_ = true; }

    /// Finalize and compute length after cbor_object::close().
    /// Reports no data if no feature was written.
    void end_encode() {
        if (w_.is_null()) {
            truncated_ = true;
            length_ = 0;
            return;
        }
        if (!feature_written_) {
            length_ = 0;
            return;
        }
        length_ = MAX_CBOR_METADATA_LEN - w_.writeable_length();
    }

    const uint8_t* get_buffer() const { return buffer_; }
    size_t get_length() const { return length_; }
    bool has_data() const { return length_ > 0; }
    bool is_truncated() const { return truncated_; }
};

#endif // CBOR_METADATA_HPP
