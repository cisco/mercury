# An Overview of the Mercury Package

*October 4, 2021*



Mercury is an open source package for network metadata capture and analysis.   It contains the standalone mercury application, the libmerc.so library, and several other supporting applications and libraries described below.

[Mercury](../src/mercury.c) is a stand-alone application for high throughput network security monitoring using Linux native AF_PACKET TPACKETv3 interface.  It can process packets at high data rates, operate off of a span port or PCAP files, capture and report metadata including fingerprints for many protocols (using this [JSON schema](schema.md)), and perform fingerprinting with destination context.

[Libmerc.so](../src/libmerc/libmerc.cc) is a shared object library that implements the packet-processing features of mercury; it can extract fingerprints and other metadata, and identify client processes and detect malware through [TLS Fingerprinting with Destination Context (FDC)](wnb.md).   



### Utilities

- [tls_scanner](../src/tls_scanner.cc) implements TLS scanning, certificate fetching for v1.3, DoH, and Domain Fronting detection.
- [cert_analyze](../src/cert_analyze.cc) reads and analyzes PKIX/X.509 certificates; it can write JSON, identify security issues with certificates, including common keys.
- [batch_gcd](../src/batch_gcd.cc) identifies common factors of RSA moduli; it can be used with cert_analyze to [find weak keys in certificates](./batch-gcd.md).
- [os_identifier](../src/os_identifier.cc) implements a multiprotocol, multisession OS fingerprinter, using a bag-of-fingerprints model.   It is not (yet) integrated into libmerc/mercury.
- [lsif](../src/lsif.cc) lists interfaces that can be monitored.  It is not (yet?) integrated into mercury.



### Supporting Applications

- [oidc](../src/libmerc/asn1/oidc.cc) is an ASN1 OID compiler that generates the C++ tables used for OID processing by libmerc and cert_analyze.
- [format](../src/format.cc) detects and reports on the data formats of input strings.
- [string](../src/string.cc) analyzes input strings; it can compute edit distance, longest common subsequences, longest common substrings, and matching (sub)substrings.  



### Test applications

- [libmerc_driver](../unit_tests/libmerc_driver.cc) is the main unit test driver for libmerc.   It is a C++ program that tests the whole libmerc 'lifecycle': it loads the libmerc.so shared object library, then uses dlsym() to load the functions in [libmerc.h](../src/libmerc/libmerc.h), then initializes libmerc, reads from a compressed resource archive, and performs a set of tests.
- [libmerc_test](../src/libmerc_test.c) is another (partly obsolete) test driver for libmerc.   It uses straight C code instead of C++.
- [archive_reader](../src/archive_reader.cc) is a test driver for the encrypted compressed archive reader (tar.gz.enc).  
- [json_object_test](../src/json_object_test.cc) is a test driver for mercury's fast JSON output code (which is implemented in [libmerc/json_object.h](../src/libmerc/json_object.h)).
- [lctrie_test](../src/libmerc/lctrie/lctrie_test.c) is a test program for the (3rd party) level compressed trie library.



### Libraries

- [libmerc](../src/libmerc/libmerc.cc) is the library for packet processing.   It can be compiled as a static library (.a) or shared object (.so).
- [mercury.cpython-38-x86_64-linux-gnu.so](../src/cython/mercury.pyx) is a shared object library that makes some mercury functions usable through python.   See the [src/cython](../src/cython) directory for more information.
- [intercept](../src/intercept.cc) is an experimental library for monitoring communications on a host.  While it is a work in progress, it is usable, and its use is documented [here](intercept.md).



## Design

Mercury identifies, extracts, and analyzes data features from network data.   It aims for efficiency (so that high bitrates and high data volumes can be supported), safety (to avoid crashes, data corruption, and vulnerabilities), and flexibility (so that support for new protocol extensions and versions is easy to add).  It also strives to minimize its dependencies; it requires neither DPDK nor libpcap to be built or run.  (Its *tests* do have some dependencies, including [jq](https://stedolan.github.io/jq/), [tcpreplay](https://tcpreplay.appneta.com/), [valgrind](https://www.valgrind.org/), [python3](https://www.python.org/), [jsonschema](https://pypi.org/project/jsonschema/), and [afl](https://lcamtuf.coredump.cx/afl/).   The [./configure](../configure) script checks for these, and omits any tests whose dependencies are not met.)     It has a modular design to allow code reuse across multiple applications (though its components could be further separated, e.g. by replacing each use of  `enum status` from libmerc.h with a local status enum).  

Mercury is written in C++17 (with some C99 code, which should be changed to C++ over time), and follows the [C++ Core Guidelines](http://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines) where possible, with some deviations for the sake of performance.  Packet processing uses compile-time polymorphism with [std::variant](https://www.cppstories.com/2018/06/variant/) (see the function tcp_data_write_json() in [pkt_proc.cc](../src/pkt_proc.cc)), which is a little ugly, but allows us to achieve polymorphism without dynamic memory allocation.

For efficiency and safety, packet data is processed using a [selective parsing](./safe-parsing.md) strategy that allows careful parsing of data, without allocating any memory on the heap.  This strategy is realized by the `class datum` in [datum.h](../src/libmerc/datum.h), which is essentially a pair of pointers to the start and end of a data field, along with member functions that support safe and efficient operations on the data.  

 Protocol Identification works by looking at the first several bytes of the packet, to see what protocol (if any) they match, and then attempting to parse the packet as that protocol.   For instance, if the first two bytes of the TCP data field are `0x16 0x03`, it could be a TLS client hello.  This pattern identification is implemented via the simple and fast method of checking mask/value pairs.   As this procedure will have some false positives (in which a packet that is not a TLS client hello will be identified as such), we rely on the fact that the method that attempts to parse the packet quickly detect those false positives.   Fortunately, selective parsing does what we need here. 

Mercury performs packet capture using the Linux kernel's native zero-copy packet processing path, [AF_PACKET TPACKET_V3](https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt), which enables high bandwidth monitoring with relatively low CPU utilization.  Currently, packet capture from network interfaces is only supported on Linux.  Packet Capture (PCAP) files are supported across platforms, with a portable implementation of a PCAP reader and writer (in [pcap_file_io.c](../src/pcap_file_io.c) and [pcap_reader.c](../src/pcap_reader.c)).

Mercury's JSON output uses a lightweight approach that avoids both std::ostream and fprintf(); instead, JSON data is written into a buffer, using the json_object and json_array classes in [json_object.h](../src/libmerc/json_object.h) to handle the formatting details, and then completed JSON lines are written as needed.   The file [json_object_test](../src/json_object_test.cc) illustrates how this is done.

As shown below, mercury sets up a number of packet processing worker threads, each of which independently processes a sequence of packets.  In live capture mode, these packets are obtained from a ring buffer that is shared between the kernel and the application.   Each packet is run through a sequence of modules.  Protocol identification detects protocols and protocol data elements of interest, based on byte patterns in the packet data.  If a protocol of interest has been found, the packet is passed on to the selective parsing stage (using a std::variant like `tcp_protocol` to represent all of the protocols of interest).  If parsing succeeds, then the object is passed to the analysis stage, and finally to the output stage, where a JSON output record is created.  Records are sent, through a lockless queue ([llq.h](../src/llq.h)) to the output thread, which uses a tournament tree to output records in increasing time order.  Files are rotated based on a count of records (and there is a feature request to rotate based on time as well).  PCAP files can be output instead of JSON records.  In a typical network security monitoring use case, the JSON output may be compressed, copied to an aggregation server, and analyzed using a tool like Spark.

![Mercury Internals](mercury-internals.png)

Most mercury processing is stateless, except for the features that track the first data packet of each TCP and UDP flow.   There is also experimental code for [on-demand TCP stream reassembly](odtcpr.md), which is a compile-time option that is off by default.

### Libmerc

Libmerc implements the packet analysis aspects of mercury, which does not include packet acquisition, file rotation, nor the tournament tree.  Its interface is defined in [libmerc.h](../src/libmerc/libmerc.h), and its [use and configuration](libmerc_config.md) is also documented.

## Use Cases

In addition to identifying client processes and malware, mercury supports the use case of [monitoring non-DNS host names for IoCs](tls-iocs.md).
