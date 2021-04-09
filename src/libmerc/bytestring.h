/*
 * bytestring.h
 *
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef BYTESTRING_H
#define BYTESTRING_H

// tell the C++ STL how to hash a basic string of uint8_t values, by
// creating a specialized struct hash<> template for that type
//
namespace std {
    template <>  struct hash<std::basic_string<uint8_t>>  {
        size_t operator()(const basic_string<uint8_t>& k) const {
            string &s = (string &)k;
            return hash<string>{}(s);
        }
    };
}

#endif // BYTESTRING_H
