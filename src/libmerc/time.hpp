// time.hpp


#ifndef TIME_HPP
#define TIME_HPP

#include "datum.h"

//
//
// UTCTime (Coordinated Universal Time) consists of 13 bytes that
// encode the Greenwich Mean Time in the format YYMMDDhhmmssZ.  For
// instance, the bytes 17 0d 31 35 31 30 32 38 31 38 35 32 31 32 5a
// encode the string "151028185212Z", which represents the time
// "2015-10-28 18:52:12"
//

class utc_time : public datum {
public:

    void fingerprint(struct buffer_stream &b) const {
        if (!is_correct_format()) {
            b.puts("malformed");
            return;
        }
        if (data[0] < '5') {
            b.snprintf("20");
        } else {
            b.snprintf("19");
        }
        b.write_char(data[0]);
        b.write_char(data[1]);
        b.write_char('-');
        b.write_char(data[2]);
        b.write_char(data[3]);
        b.write_char('-');
        b.write_char(data[4]);
        b.write_char(data[5]);
        b.write_char(' ');
        b.write_char(data[6]);
        b.write_char(data[7]);
        b.write_char(':');
        b.write_char(data[8]);
        b.write_char(data[9]);
        b.write_char(':');
        b.write_char(data[10]);
        b.write_char(data[11]);
        b.write_char(data[12]);

    }

    bool is_correct_format() const {
        if (this->length() != 13) {
            return false;
        }
        return isdigit(data[0])
            & isdigit(data[1])
            & isdigit(data[2])
            & isdigit(data[3])
            & isdigit(data[4])
            & isdigit(data[5])
            & isdigit(data[6])
            & isdigit(data[7])
            & isdigit(data[8])
            & isdigit(data[9])
            & isdigit(data[10])
            & isdigit(data[11])
            & (data[12] == 'Z');
    }

};

//  For the purposes of [RFC 5280], GeneralizedTime values MUST be
//  expressed in Greenwich Mean Time (Zulu) and MUST include seconds
//  (i.e., times are YYYYMMDDHHMMSSZ), even where the number of
//  seconds is zero.
//
class generalized_time : public datum {
public:

    void fingerprint(struct buffer_stream &b) const {
        if (!is_correct_format()) {
            b.puts("malformed");
            return;
        }
        b.write_char(data[0]);
        b.write_char(data[1]);
        b.write_char(data[2]);
        b.write_char(data[3]);
        b.write_char('-');
        b.write_char(data[4]);
        b.write_char(data[5]);
        b.write_char('-');
        b.write_char(data[6]);
        b.write_char(data[7]);
        b.write_char(' ');
        b.write_char(data[8]);
        b.write_char(data[9]);
        b.write_char(':');
        b.write_char(data[10]);
        b.write_char(data[11]);
        b.write_char(':');
        b.write_char(data[12]);
        b.write_char(data[13]);
        b.write_char(data[14]);

    }

    bool is_correct_format() const {
        if (this->length() != 15) {
            return false;
        }
        return isdigit(data[0])
            & isdigit(data[1])
            & isdigit(data[2])
            & isdigit(data[3])
            & isdigit(data[4])
            & isdigit(data[5])
            & isdigit(data[6])
            & isdigit(data[7])
            & isdigit(data[8])
            & isdigit(data[9])
            & isdigit(data[10])
            & isdigit(data[11])
            & isdigit(data[12])
            & isdigit(data[13])
            & (data[14] == 'Z');
    }

};


/// sets the generalized time string \param gt to the equivalent value
/// of the utc time string \param utc
///
static void utc_to_generalized_time(uint8_t gt[15], const uint8_t utc[13]) {
    if (utc[0] < '5') {
        gt[0] = '2';
        gt[1] = '0';
    } else {
        gt[0] = '1';
        gt[1] = '9';
    }
    memcpy(gt + 2, utc, 13);
}

#endif // TIME_HPP
