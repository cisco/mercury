// json_string.hpp
//

#ifndef JSON_STRING_HPP
#define JSON_STRING_HPP

#include <string>             // for std::string
#include <cstring>            // for memcmp()
#include <json_object.h>      // for json_object, used in unit_test
#include <buffer_stream.h>    // for buffer_stream

/// implements a \ref buffer_stream that uses a `std::string` as its
/// underlying data storage
///
class json_string {
    std::string str;
    buffer_stream buf;

public:

    /// construct a `json_string` of length \param buf_size
    ///
    json_string(size_t buf_size);

    /// return a `std::string` containing the data written into the
    /// buffer_stream, if no truncation occurred during that writing,
    /// or the empty JSON object "{}" otherwise.
    ///
    /// note: this function call modifies the contents of the object
    /// by resizing it (if no truncation has occured when writing json
    /// data to the string) or setting it to "{}" (if truncation has
    /// occured)
    ///
    std::string get_string();

    /// convert a `json_string` into a pointer to a buffer_stream, for
    /// use in initializing a `json_object` or `json_array`
    ///
    operator buffer_stream *() { return &buf; }

    /// performs a unit test of the class `json_string` and returns
    /// `true` if it passes, and `false` otherwise.
    ///
    inline static bool unit_test();

};

// class json_string implementation
//
inline json_string::json_string(size_t buf_size) :
    str(buf_size, '\0'),
    buf{str.data(), (int)str.length()}
{ }

inline std::string json_string::get_string() {
    if (buf.trunc) {
        //
        // the attempted write failed, so set the string to an empty
        // json_object to ensure valid output
        //
        str = "{}"; // error: buffer is truncated
    } else {
        //
        // resize the string to reflect the length of the JSON text
        // written into it
        //
        str.resize(buf.doff);
    }
    return str;
}

bool json_string::unit_test() {

    auto test = [](size_t buflen, const char *expected_output) {
        // create string_buffer_stream
        //
        json_string buf{buflen};

        // attempt to write a json_object into the buffer
        //
        json_object o{buf};
        o.print_key_string("test", "example");
        o.close();

        // verify
        //
        std::string output_str = buf.get_string();
        if (memcmp(output_str.data(), expected_output, strlen(expected_output)) != 0) {
            return false;
        }

        return true;
    };
    if (test(19, "{\"test\":\"example\"}") != true) {
        return false;
    }
    if (test(18, "{}") != true) {
        return false;
    }

    return true;
}


#endif // JSON_STRING_HPP
