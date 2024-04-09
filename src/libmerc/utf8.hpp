// utf8.hpp
//

#ifndef UTF8_HPP
#define UTF8_HPP

#include "datum.h"
#include "buffer_stream.h"

class utf8_string : public datum {
public:
    utf8_string(datum &d) : datum{d} { }

    void fingerprint(struct buffer_stream &b) const {
        if (datum::is_not_null()) {
            b.write_utf8_string(data, length());
        }
    }
};

#endif // UTF8_HPP
