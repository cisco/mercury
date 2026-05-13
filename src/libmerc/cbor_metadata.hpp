// cbor_metadata.hpp
//
// CBOR metadata buffer manager for encoding per-packet feature data.

#ifndef CBOR_METADATA_HPP
#define CBOR_METADATA_HPP

#include "cbor.hpp"

/// Fixed-buffer CBOR writer for per-packet metadata. Opens an outer
/// indefinite map on reset(), exposes a writeable for feature encoding,
/// and closes the map on end_encode().
class cbor_metadata_context {
    static constexpr size_t MAX_CBOR_METADATA_LEN = 4096;

    uint8_t buffer_[MAX_CBOR_METADATA_LEN];
    writeable w_;
    size_t length_ = 0;
    bool truncated_ = false;

public:
    cbor_metadata_context() : buffer_{}, w_{} {}

    /// Reset buffer and open outer indefinite map (0xBF).
    void reset() {
        w_ = writeable{buffer_, buffer_ + MAX_CBOR_METADATA_LEN};
        length_ = 0;
        truncated_ = false;
        w_.copy(0xbf);  // indefinite-length map
    }

    /// Get writeable for feature classes to write key+value pairs into.
    writeable& get_writer() { return w_; }

    /// Close the outer indefinite map (0xFF) and finalize length.
    void end_encode() {
        if (w_.is_null()) {
            truncated_ = true;
            length_ = 0;
            return;
        }
        w_.copy(0xff);  // break code — end of indefinite map
        if (w_.is_null()) {
            truncated_ = true;
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
