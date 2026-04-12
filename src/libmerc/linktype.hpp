// \file linktype.hpp
//

#ifndef LINKTYPE_HPP
#define LINKTYPE_HPP

/// A `LINKTYPE` is a 16-bit integer enumeration that specifies a type
/// of packet encapsulation.
///
/// `LINKTYPE` values are specified in
/// https://datatracker.ietf.org/doc/draft-ietf-opsawg-pcaplinktype/.
/// While these values are not formally part of any standard, their
/// usage is widespreak and stable, dating back to the seminal
/// libpcap/tcpdump work before 1990.
///
enum LINKTYPE : uint16_t {
    NULL_       =    0,  // BSD loopback encapsulation
    ETHERNET    =    1,  // Ethernet
    PPP         =    9,  // Point-to-Point Protocol (PPP)
    RAW         =  101,  // Raw IP; begins with IPv4 or IPv6 header
    LINUX_SLL   =  113,  // Linux "cooked" capture encapsulation
    NONE        = 65535  // reserved, used here as 'none'
};

#endif // LINKTYPE_HPP
