# An Overview of the Mercury Package

*October 1, 2021*



Mercury is an open source package for network metadata capture and analysis.   It contains the standalone mercury application, the libmerc.so library, and several other supporting applications and libraries described below.

Mercury is a standalone application for high throughput network security monitoring using Linux native AF_PACKET TPACKETv3 interface.  It can process packets at high data rates, operate off of a span port or PCAP files, capture and report metadata including fingerprints for many protocols, and perform fingerprinting with destination context.

Libmerc.so, a shared object library that can identify client processes and detect malware through TLS fingerprinting with destination context (FDC).



### Utilities

- [tls_scanner](../src/tls_scanner.cc) implements TLS scanning, certificate fetching for v1.3, DoH, and Domain Fronting detection.
- [cert_analyze](../src/cert_analyze.cc) reads and analyzes PKIX/X.509 certificates; it can write JSON, identify security issues with certificates, including common keys.
- [batch_gcd](../src/batch_gcd.cc) identifies common factors of RSA moduli; it can be used with cert_analyze to find weak keys in certificates.
- [os_identifier](../src/os_identifier.cc) implements a multiprotocol, multisession OS fingerprinter, using a bag-of-fingerprints model.   It is not (yet) integrated into libmerc/mercury.
- [lsif](../src/lsif.cc) lists interfaces that can be monitored.



### Supporting Applications

- [oidc](../src/libmerc/asn1/oidc.cc) is an ASN1 OID compiler that generates the C++ tables used for OID processing by libmerc and cert_analyze/
- [format](../src/format.cc) detects and reports on the data formats of input strings.
- [string](../src/string.cc) analyzes input strings; it can compute edit distance, longest common subsequences, longest common substrings, and matching (sub)substrings.  

### Test applications

- libmerc_driver is the main unit test driver for libmerc
- libmerc_test is another test driver for libmerc
- archive_reader is a test driver for the encrypted compressed archive reader (tar.gz.enc)
- json_object_test is a test driver for the JSON output code
- lctrie_test is a test program for the (3rd party) level compressed trie library
- json_reader is an obsolete JSON test driver

### Libraries

- libmerc is the library for packet processing
- intercept is an experimental library for monitoring host communications
- python/cython



## Design

Mercury identifies, extracts, and analyzes data features from network data, with the secondary aims of efficiency (so that high bitrates and high data volumes can be supported), flexibility (so that support for new protocol extensions and versions is easy to add),  and safety (to avoid crashes, data corruption, and )



Selective packet parsing

![](/media/mcgrew/linux-ssd/mercury-transition/doc/mercury-internals.png)