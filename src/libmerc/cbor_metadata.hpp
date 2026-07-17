// cbor_metadata.hpp
//
// CBOR metadata buffer manager for encoding per-packet feature data.

#ifndef CBOR_METADATA_HPP
#define CBOR_METADATA_HPP

#include "cbor.hpp"   // pulls in datum.h (dynamic_buffer, writeable)

/// per-packet CBOR metadata writer. Capacity is fixed at construction and the
/// backing buffer is rewound (not reallocated) per packet, so its base pointer
/// is stable for the object's lifetime. A zero capacity means the feature is
/// off and no buffer is allocated.
class cbor_metadata_context {
    static constexpr size_t DEFAULT_CBOR_METADATA_LEN = 4096;

    dynamic_buffer buf_;
    size_t capacity_ = 0;      // 0 when the feature is disabled
    size_t length_ = 0;
    bool truncated_ = false;
    bool feature_written_ = false;

    static size_t resolve_capacity(bool enabled, size_t size) {
        if (!enabled) { return 0; }
        return (size != 0) ? size : DEFAULT_CBOR_METADATA_LEN;
    }

    // delegating target: buf_ and capacity_ share one value
    explicit cbor_metadata_context(size_t capacity)
        : buf_{capacity}, capacity_{capacity} {}

public:
    /// \param enabled  allocate a buffer only when the feature is on
    /// \param size     capacity in bytes; 0 selects the default
    explicit cbor_metadata_context(bool enabled = false, size_t size = 0)
        : cbor_metadata_context(resolve_capacity(enabled, size)) {}

    /// rewind the buffer for a new packet
    void reset() {
        if (capacity_ == 0) { return; }
        buf_.reset();
        length_ = 0;
        truncated_ = false;
        feature_written_ = false;
    }

    /// writeable for cbor_object to write into.
    writeable& get_writer() { return buf_; }

    /// bytes written so far; 0 if disabled or if a write overran the buffer
    size_t bytes_written() const {
        return (capacity_ == 0) ? 0 : (size_t)buf_.readable_length();
    }

    /// mark that a feature (not just the header) is present in the buffer
    void set_feature_written() { feature_written_ = true; }

    /// finalize length after the outer cbor_object is closed
    void end_encode() {
        if (capacity_ == 0) { return; }
        // check truncation first: an overrun nulls the buffer, and
        // readable_length() then reads 0 rather than a stale full length.
        if (buf_.is_null()) {
            truncated_ = true;
            length_ = 0;
            return;
        }
        if (!feature_written_) {
            length_ = 0;   // header only, nothing to deliver
            return;
        }
        length_ = (size_t)buf_.readable_length();
    }

    const uint8_t* get_buffer() const { return buf_.contents().data; }
    size_t get_length() const { return length_; }
    bool has_data() const { return length_ > 0; }
    bool is_truncated() const { return truncated_; }
};

#endif // CBOR_METADATA_HPP
