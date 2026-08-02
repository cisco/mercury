// cbor_metadata.hpp
//
// CBOR metadata buffer manager

#ifndef CBOR_METADATA_HPP
#define CBOR_METADATA_HPP

#include "cbor.hpp"   // pulls in datum.h (dynamic_buffer, writeable)

/// \brief holds a fixed-capacity buffer for holding CBOR-encoded data.
///
/// \note The function reset() re-initializes the buffer, whose base address is
/// stable for the object's lifetime.
///
class cbor_metadata_buffer {
    dynamic_buffer buf_;
    bool enabled_ = false;
    bool feature_written_ = false;

public:
    /// capacity used when no size is given
    ///
    static constexpr size_t DEFAULT_CBOR_METADATA_LEN = 4096;

    /// constructs a buffer with a capacity of \param size bytes; a size of
    /// zero disables the feature and allocates nothing
    ///
    explicit cbor_metadata_buffer(size_t size = DEFAULT_CBOR_METADATA_LEN)
        : buf_{size}, enabled_{size != 0} {}

    // Disallow copy/move: dynamic_buffer (via its writeable base) caches pointers into its
    // internal vector; copying/moving would leave those pointers stale.
    //
    cbor_metadata_buffer(const cbor_metadata_buffer&) = delete;
    cbor_metadata_buffer& operator=(const cbor_metadata_buffer&) = delete;
    cbor_metadata_buffer(cbor_metadata_buffer&&) = delete;
    cbor_metadata_buffer& operator=(cbor_metadata_buffer&&) = delete;

    /// rewinds this buffer for a new packet; call once, before any writes for that
    /// packet, or the accessors report the previous packet's bytes as current
    void reset() {
        if (!enabled_) { return; }
        buf_.reset();
        feature_written_ = false;
    }

    /// returns the \ref writeable that cbor_object writes into
    ///
    writeable& get_writer() { return buf_; }

    /// returns the number of bytes written so far, or zero if this buffer is
    /// disabled or a write overran it
    ///
    size_t bytes_written() const {
        return enabled_ ? (size_t)buf_.readable_length() : 0;
    }

    /// records that a feature, and not just the header, was written
    ///
    void set_feature_written() { feature_written_ = true; }

    /// returns a pointer to the encoded bytes
    ///
    const uint8_t* get_buffer() const { return buf_.contents().data; }

    /// returns the deliverable length, or zero if this buffer is disabled, a
    /// write overran it, or no feature was written
    ///
    /// \note read after the `cbor_object`s are closed, or the length is short
    /// by their break bytes.
    ///
    size_t get_length() const {
        return (enabled_ && feature_written_ && !buf_.is_null())
            ? (size_t)buf_.readable_length() : 0;
    }

    /// returns true if there is anything to deliver
    ///
    bool has_data() const { return get_length() > 0; }

    /// returns true if a write overran this buffer; sticky until \ref reset()
    ///
    bool is_truncated() const { return enabled_ && buf_.is_null(); }
};

#endif // CBOR_METADATA_HPP
