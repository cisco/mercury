# LC-Trie, Level Compressed Tries for IPv4 Subnet Matching

This project provides a level compressed trie C library
for the purposes of matching IP addresses to arbitrarily
define IPv4 CIDR subnets.  Various address types are
supported, and the library has the RFC 1918 private IPv4
address space as well as the remaining RFC 5735 special
IPv4 address ranges hard coded into an auxiliary IPv4
information module.

For our purposes, it should be sufficient to dump the trie
and start from scratch again if we want to rebuild the trie.
This will correspond to a front/back buffer should this need
to be wired into a performance critical asynchronous system.

--

## Instructions

### How to Build

Build requirements:
make, GCC, glibc

To build:
On any relatively modern unix system, simply typing make should
produce the lctrie_test executable binary.

### How to Run

./lctrie_test bgp/data-raw-table

This will use the raw APNIC BGP prefix table, run some basic
tests against the library, and then conduct a 5 second performance
test against the library with randomized lookup addresses.

Performance metrics and runtime stastics will be produced at the
end of each runtime step.

--

## Copyright and License

This project is copyright 2016 Charles Stewart <chuckination@gmail.com>.

Software is licensed under [2-Clause BSD Licnese](https://github.com/chuckination/lctrie/blob/master/LICENSE).

--

### Bibliography

* BGP Routing Table Analysis - Washington, Asia Pacific Network Information Centre, 2016

--http://thyme.apnic.net/us/

* Stefan Nilsson and Gunnar Karlsson, IP-Address Lookup Using LC-Tries, KTH Royal Institute of Technology, 1998

--https://www.nada.kth.se/~snilsson/publications/IP-address-lookup-using-LC-tries/text.pdf

* Stefan Nilsson and Gunnar Karlsson, Fast IP Routing with LC-Tries, Dr. Dobb's, 1998

--http://www.drdobbs.com/cpp/fast-ip-routing-with-lc-tries/184410638

* Weidong Wu, Packet Forwarding Technologies, CRC Press, 2007

* RFC 1519, Classless Inter-Domain Routing (CIDR), IETF, 1993

--https://tools.ietf.org/html/rfc1519

* RFC 4632, Classless Inter-Domain Routing (CIDR), IETF, 2006

--https://tools.ietf.org/html/rfc4632

* RFC 5735, Special Use IPv4 Addresses, IETF, 2010

--https://tools.ietf.org/html/rfc5735

* RFC 1918, Address Allocation for Private Internets, IETF, 1996

--https://tools.ietf.org/html/rfc1918
