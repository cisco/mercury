# CHANGELOG for Mercury
* Code changes to support parsing pppoe packets from library interface
  mercury_packet_processor_get_analysis_context
* Code changes to report dtls hello verify request in l7 metadata and
  revamped dtls fingerprint format

## VERSION 2.11.1
* Fixed crypto assessment handling of GREASE extensions. Optimized the crypto
  assessment processing to produce clean JSON output in a single pass.
* Added proper UTF-8 escaping of user-agent strings during stats reporting.

## VERSION 2.11.0
* Added SNMP protocol identification with JSON and CBOR output.
* Added Syslog protocol identification with JSON and CBOR output.
* Report a password-recovery string for TACACS+ protocol.
* Added decimal_integer class to provide text-to-integer functionality suitable
  for packet processing. The class includes error checking and avoids copying,
  exception throwing, or memory allocation.
* Improved configuration file parsing robustness to handle malformed input.
* Removed adaptive random packet drop feature, which is no longer used
  and probably not appropriate for current mercury scenarios.
* Removed usage of deprecated OpenSSL APIs and adopted recommended OpenSSL 3.x
  interfaces whenever a sufficiently new OpenSSL version is available.
* Removed obsolete Python scripts.
* Added examples.cpp to provide example usage of data parsing classes.
* Replaced class literal<> with a more efficient but otherwise equivalent class.

## VERSION 2.10.0
* Added defensive code around memcpy operations in QUIC reassembly.
* Exempted private IP addresses from Domain Faking check.
* Enhanced protocol matcher and SMTP enhancements to support more commands.
* Fixed compilation of experimental tool intercept.so.
* Integrated STUN classifier into Mercury's analysis path.
* Extended DHCP to report on all message types, not just responses.
* Bugfix: removed user_agent reset code from do_observation struct.
* STUN fingerprints are generated for client requests but not server responses.

## VERSION 2.9.0
* Added a new configuration option, network-behavioral-detections,
  which enables behavioral detections without a resources file.
* Added code to identify residential proxies through random nonces.
* Fixed a bug in the cython interface that resulted in all HTTP packets being
  labeled as FakeTLS when using the analyze_packet(bytes pkt_data) function.
* Added a feature to the libmerc utility that can generate layer 7 metadata
  using libmerc_util --fdc.  This does not affect the normal output of mercury or
  libmerc, but is useful in other integrations.
* Bug fix to clean up reassembly flow state before processing new flow. Affects
  layer 7 metadata processing.
* Internal code refactoring: encapsulate all softmax functionality (including
  XSIMD) into its own header file.
* Build improvements: Graceful detection of python dependencies. Partial fix for
  intermittent ASAN crash on repeated dlopen/dlclose of libmerc, which may have
  been an interaction between dlclose and ASAN. Fix CMake build for windows and
  add CMake support for non-standard OpenSSL library installations. Fix buffer
  overread in OID compiler, which is run only at compile time.
* Clean analysis context and reassembly flow, before packet processing,
  to clean stale content from previous flows.

## VERSION 2.8.1
* Bug fixes: ASAN container overflow in stats collection, dangling reference in
  Naive Bayes classifier weights, faulty unit test for resource file version.
* Disabled Fake TLS detection for QUIC.  Will re-enable when feature is ready.
* Added fdc (fingerprint and destination context) tests to code coverage report.
* Added internal CBOR encoding classes with translation to JSON and a
  key-compaction option.
* Changed the order of domain name normalization in the classifier to normalize
  a FQDN before extracting the domain name.

## VERSION 2.8.0
* Fixed `get_json_decoded_fdc()` to not assume UTF-8 inputs.
* Added CBOR encoding/decoding for SSH and STUN fingerprints.
* Fixing compiler warnings related to ABI differences
* CMake changes required to add xsimd as submodule and fixing
  windows compilation issues
* Removed duplicate UTF-8 and IP address output code used in
  ASN.1, added classes `utc_time`, `generalized_time`, and `raw_oid`
  to facilitate JSON output, removed `json_object_asn1` and
 `json_array_asn1` and some unused function definitions and
  declarations.
* Added changes to leverage SIMD instructions to improve
  performance. Added xsimd library as a git submodule
* Removed some direct calls to `fprintf(stderr, ...)` from `libmerc.so`.
* Added experimental support for building mercury on macOS Apple Silicon. (Note:
  interface capture is disabled, since AF_PACKET is Linux specific.)

## VERSION 2.7.1
* Updated QUIC reassembly logic for reordered QUIC crypto frames
* Refactored the IP subnet reading code to minimize the amount of
  temporary RAM needed
* Added a new configuration option, minimize-ram, which reduces
  the RAM usage of mercury library when enabled
* Added changes to allow classifier to use custom weights
  and introduced new cython interface
* Added additional fuzz tests. Updated the `generate_fuzz_test.sh` script to
  support generating fuzz functions that test functions requiring two fuzzed inputs.
  Also hardened some datum functions.
* Added `test-coverage` and `test-coverage-fuzz` targets to generate a
  comprehensive code coverage report for the Mercury library.

## VERSION 2.7.0
* Added minimal RDP (Remote Desktop Protocol) support, which
  reports information about handshakes, security negotiation, and
  cookies.
* Added minimal VNC/RFB (Virtual Network Computing / Remote Frame
  Buffer) support, which reports handshakes and versions.
* Added MySQL Login support, to report on exposed credentials.
* Added TACACS+ support, which reports on both `encrypted` and
  `unencrypted` messages.  Details of unencrypted authenticationd
  messages are reported in JSON.
* Added minimal TFTP support, which reports file names and modes.
* Extended FTP command channel to multi-line responses.
* Support for reporting outer tunnel parameters and also includes
  support for PPoE, VXLAN encapsulation and IP encapsulations.

## VERSION 2.6.5
* Added support for mutli-line FTP responses.
* Fixed memory leak associated with Domain Faking detection
  initialization corner case, and reinstated resource archive version qualifier count.
* Fixed issues discovered by fuzz testing, and added unit test cases.
* Added many new fuzz tests, plus the helper template function `json_output_fuzzer<>()`.
  No changes to behavior, though some function signatures were extended with an optional `bool metadata`.

## VERSION 2.6.4
* Added reporting of HTTP CONNECT proxies in JSON output.
* Added FTP command channel reporting in JSON output.
* Added SSH crypto assessment.
* Refactored weighted naive bayes classifier and eliminated
  intermedate data structures that had been used during
  initialization.
* Several minor fixes and defensive coding additions
* Added normalization for TLS/QUIC Server Names and HTTP Hosts
* Added test cases for CBOR.
* Improved error checking and unit test cases for IPv4 and IPv6 address textual representations.
* Added detectors for Domain Faking and Fake TLS.

## VERSION 2.6.3
* Revamped SSH metadata and fingerprints.
* Minor improvements to reassembly.
* Numerical stability improvements to the naive bayes classifier.
* Added [`classify`](src/classify.cpp) tool for running classifier
  on a command-line arguments.
* Minor fixes to reassembly and LDAP parsing

## VERSION 2.6.2
* Removed default interface from template configuration file
  `mercury.cfg` and added runtime check to require that an interface
  be specified when a configuration file is used.
* Added `--crypto-assess=<policy>` option, which implements an
  assessment of the cryptographic security of TLS, DTLS, and QUIC
  sessions and clients.  The currently implemented policies are
  `quantum_safe` and `quantum_safe_verbose`.  The former is the
  default, and the latter provides human-readable names.
* Integrated support for the IPSec protocols IKEv2 and ESP.
* Integrated minimal LDAP support, which provides details only for
  `bindRequest` and `bindResponse` messages.
* Added support for the `LINKTYPE_LINUX_SLL` (Linux 'Cooked Capture').
* Improved the `stats` test to avoid spurious failues, by allowing
    mercury JSON output and mercury stats counts to differ by up to
    10% due to lossy stats collection.
* Enabled `--raw-features` and `--reassembly` to be enabled through
  the configuration file.
* Refactored `pmercury` to use `c++` code where possible.
* Re-enabled ^C signal handler for PCAP processing.
* Moved `dns.id` and `ip.id` fields to the tail end of the JSON
  record, to improve Parquet compressibility.
* Classification improved to allow multiple fingerprints to utilize
  the same Weighted Naive Bayes models.
* Various internal improvements and unit test tweaks.

## VERSION 2.6.1
* Improved STUN implementation: added test cases, fixed fingerprint
  feature nits, renamed variables for consistency with the RFCs, and
  simplified the message_type check.

## VERSION 2.6.0
* Added reassembly for QUIC initial messages, to ensure metadata and
  fingerprint capture even for very long messages (e.g. due to
  quantum-safe cryptography or encrypted client hellos).
* Added the `--reassembly` keyword, which applies to both TCP and
  QUIC, and retired the `--tcp-reassembly` option.
* Improved support for the STUN protocol.
    * Added support for "classic" (RFC3489) STUN.  In classic STUN,
      `stun.magic_cookie` field is `false` and the
      `stun.transaction_id` field is 16 bytes long.  In modern STUN,
      the former field is `true` and the latter is 12 bytes long.
    * Added a STUN fingerprint that uses data features selected by
      automated feature-mining fingerprint.
    * The STUN "usage" (STUN/TURN/ICE/etc.) is reported in the new
      `stun.usage` field.
    * Details are now reported for the STUN
      attributes `BANDWIDTH`, `SOURCE-ADDRESS`, `CHANGED-ADDRESS`,
      `RESPONSE-ADDRESS`, and `REFLECTED-FROM`.
    * The `stun.message_type` field has been renamed to `stun.class`.
* Added new output fields `dns.id`, `ip.version`, `ip.id`, `ip.ttl`
  that are present when the `--metadata` option is used.
* Added a `--raw-features=<protocols>` command line option that
      specifies which protocols should have a raw feature vector
      output.  Currently supported options include `bittorrent`,
      `smb`, `ssdp`, `stun`, `tls`, `all`, and `none`.
* Refactored HTTP header processing, enabling
    * Non-standard delimeters are accepted, and their value is reported.
    * HTTP 0.9 is accepted.
    * With the `--metadata` option, all of the headers are output
      using an object to represent each key/value pair.  This
      simplifies the processing of header keys that appear more than
      once in an HTTP request or response.
* Added the first 512 bytes of the HTTP Body to `http` JSON records
* Added BSD Loopback support for GENEVE.
* Improved `tofsee` message format checking and `--stats` reporting.
* Fixed the UTF-8 fuzz test seed file locations.
* Changes to fingerprint and destination statistics output (`--stats`)
    * Removed source IP address (`src_ip`) anonymization in stats file output.
    * When processing a PCAP file, stats now uses lossless (blocking)
      processing of events.  This enables the stats test to be
      deterministic, avoiding occasional spurious failures during `make test`.
    * Increased stats message queue size from 256 to 512.
    * Stats aggregator now uses adaptive sleep time.
    * Makefile addition: pre-clean the `test/` directory before
      running the stats test.  This prevents leftover files in the
      test directory from throwing off the counts of mercury JSON
      output vs. mercury stats output.
* The `--select=all` configuration option now actually selects all
  protocols, including layer 2 protocols like ARP.
* Added the `event_start` timestamp field to layer 2 JSON records.
* Improved signal handling for code safety.
* TLS ALPN GREASE is now normalized to `0x0a0a (\n\n)`.
* In `libmerc`, truncated fingerprints now have a `fingerprint_status`
  set to `fingerprint_status_unlabeled`.
* Added informational messages to `libmerc`: resource file load time,
  total number of loaded fingerprints, and the end time of a telemetry
  stats dump.
* Moved `hasher` to `crypto_engine.h`, so that it is more accesible.


## Version 2.5.31
* Mercury now outputs `tls.client.certs` and `tls.undetermined.certs`
  as well as `tls.server.certs`, for TLS version 1.2 and earlier.
  Client and server certificate chains are distinguished by the
  handshake type of the key exchange data that follows the
  `Certificate` data.  If no key exchange data is present, then the
  certificate is reported as `tls.undetermined.certs`.
* Timestamp counter reading support for ARM added in
  [tsc_clock.hpp](src/libmerc/tsc_clock.hpp).
* If a timestamp of `0` is passed to `libmerc`, a timestamp is
  computed in order to improve the reassembly of TCP messages, as needed.

## Version 2.5.30
* Dramatic improvements to TCP reassembly for output, performance and TCP segments handling.
* Improved error handling for malformed UTF-8 strings encountered in protocol fields.
* Support to parse and output an Encrypted Client Hello extension features.
* Concise Data Definition Language (CDDL) definitions for Network Protocol Fingerprinting.
* Concise Binary Object Representation (CBOR) encoding and decoding for fingerprints and Fingerprint and Destination Context.
* Support for reading classifier feature weights from resource file, whenever available.

## Version 2.5.29
* Support for "dual DB" resource archives, as described in
  [doc/resources.md](../doc/resources.md).
* Dramatic improvements to mercury's scalability, due to a lockless
  ring buffer for output, and output buffers that scale to 20% of the
  requested memory.  JSON output records may now have `event_start`
  times that are slightly out of order, as the tournament tree that
  had been used to ensure ordering across threads has been removed.
* Significant improvements to error detection, recovery and reporting,
  including stall detection and recovery for packet-processing
  threads, thread ID reporting, more detailed I/O statistics, and
  accounting for output drops and output file rotation.

## Version 2.5.28
* Added decapsulation support for GENEVE (RFC 8926)
* Added a log message that indicates the end of a stats dump, and one that reports the total number of fingerprints of each type in resource file.
* Disabled the TLS "feature" output, to reduce output volume.
* Added a commit hash output to `mercury --version`
* Added a check that the resource archive contains a watchlist, and added an empty watchlist to `resources/resources.tgz`.
* Added a Makefile target for the Cryptographic Message Syntax (CMS) reader `src/cms`.
* Minor fixes to output and documentation.

## Version 2.5.27

* Changes to enable native builds on MacOS for both Intel and Apple Silicon.
* Fixes and extensions to fuzz testing, and additions so that the `fuzz-test` target in [test/Makefile.in](../test/Makefile.in) can be used by Jenkins.
* Tofsee fingerprints are now reported through the `stats` output.
* The `tls/2` and `quic/1` fingerprints were revamped to include the QUIC extension ffa5.
* GREASE normalization for `tls/1` was fixed.
* The equivalence class normalization for `dst_port` was removed.

## Version 2.5.26

* Added SOCKS v4 and v5 identification and metadata reporting.
* Added `tls/2` and `quic/1` fingerprint definitions.
* Added DNS SVCB parsing.
* Fixed SMB special character escaping.
* Adjusted classifier malware probability estimation logic to better handle the case where there are few labeled benign samples.
* Minor additions to internal classes and functions.

## Version 2.5.25

* Fingerprints are reported for Tofsee initial messages as `tofsee/generic`.
* Improved portability by adding `#include <cstdint>` where needed.

## Version 2.5.24

* Minor improvement to the classifier's numerical accuracy.
* Reduced mercury's output tournament's max delay from 5s to 100ms.
* Reduced libmerc `#include` file dependencies.

## Version 2.5.23

* (Significantly) improved the encrypted/compressed archive reader speed.
* Process attributes now reported through the `mercury_packet_processor_get_attributes` function.

## Version 2.5.22

* JSON records created from incomplete TCP segments are now highlighted with `"reassembly_properties": { "truncated": true }`.
* Improved TCP segment handling.
* Removed inappropriate output regarding truncation in X509 certificates.

## Version 2.5.21

* Fixed a slow memory leak in TCP reassembly
* Optimized LRU cache in `fingerprint_prevalence::update()`, and changed locking strategy to minimize thread contention
* New cython function `perform_analysis_with_weights`

## Version 2.5.20

* Added support to parse IP pkts encapsulated in SGT or Cisco Metadata.
* Added a depth limit to the parsing of nested bencoding in Bittorrent protocol.

## Version 2.5.19

* Improvements to `tls_scanner`, `batch_gcd`, and `cert_analyze`.
* Improved fuzz test coverage.
* Fixed minor typos and pluralization in JSON output.
* Portability changes to enable compilation (of some files) on Windows.

## Version 2.5.18

* Added experimental support for detecting and decoding Tofsee initial messages.  Use the option --nonselected-tcp-data to enable this feature.
* Added support for mySQL and MariaDB initial messages.
* Removed C-language comment from the LICENCE file.
* Fixed bug that caused DNS responses to sometimes be reported as queries.
* Improved cython support for building PIP packages.
* Extended the intercept library to detect and report on more protocol types.
* Increased the size of the internal data buffers in the intercept library to accomodate larger messages.
* Minor improvements to SMB2, IEC, SSDP, and documentation.
* Refactored some code for extensibility, code re-use, and clarity.

## Version 2.5.17

* Fixed a libmerc.so issue with extended configuration parsing.

## Version 2.5.16

* Fixed a libmerc.so issue with fingerprint format versions.

## Version 2.5.15

* Add support for the OpenVPN protocol over TCP; the `--select` command can be configured for that protocol with `openvpn_tcp`.
* Fixed an OpenSSL issue that would sometimes affect QUIC processing, by adding conditional compilation to handle older and newer versions of that library.  The ./configure script now sets the variable SSLNEW, when the required newer data structures are found.
* Refactored HTTP for improved performance.

## Version 2.5.14

* When --analysis is used, the TLS fingerprint format in the resource file is detected, and that format will be used to process packets.  The `--format` option, if present, will be overriden.

## Version 2.5.13

* Added `--format` option that selects the fingerprint format(s).
* Added `tls/1` fingerprint format, in which extensions are sorted into increasing lexicographic order.  This compensates for TLS clients that randomize the order of extensions.
* Updated and amended this README.

## Version 2.5.12

* Fixes some bugs.
* Updated and amended this README.

## Version 2.5.11

* Run-time configurability for Genric Routing Encapsulation (GRE), Cisco Discovery Protocol (CDP), Link-Layer Discovery Protocol (LLDP), Address Resolution Protocol (ARP), Open Shortest Path First (OSPF), NetBIOS Datagram Service (NBDS), NetBIOS Streaming Service (NBSS), Stream Control Transmission Protocol (SCTP), and the Internet Control Message Protocol (ICMP).  These protocols are off by default; they must explicitly appear in the `--select` option to be selected.
* STUN and DNP3 introduce a new convention for reporting unknown type codes in JSON by including the hexadecimal value of the unknown code as a string, such as `"type":"UNKNOWN (0004)"`.  This convention allows for a smaller and simpler schema, since no additional fields are needed to report unknown values.
* Support for the [automatic generation of C++ classes that represent type codes](doc/autogen.md) from Comma Separated Value (CSV) files, in the [src/tables](src/tables) directory.  This facility is currently used by STUN and IKE.
* Experimental support for IKEv2.
* Fuzz tests now run in parallel, making that process considerably faster.  Additional fuzz tests were added.

## Version 2.5.10

* Fixes some bugs.
* Updated and amended this README.

## Version 2.5.9

* Support for detecting, parsing, and reporting STUN packets as JSON.  Fingerprinting for STUN is experimental.

## Version 2.5.8

* Added fuzz testing framework based on libfuzz.  This replaces AFL in the `make fuzz-test` target in `test/`.
* Support for on-demand TCP reassembly of TLS Client Hello packets and other metata.  This feature is configured with the --tcp-reassembly option.
* Support for detecting DNS over TCP packets and reporting that data in the JSON output.
* Support for detecting SMB v1 and v2 and reporting the fields of the negotiate request and response packets in the JSON output.
* Support of detecting IEC 60870-5-104 packets and reporting its fields in the JSON output.

## Version 2.5.7

* Support for detecting SSDP and reporting relevant fields in the JSON ouput.

## Version 2.5.6

* QUIC salt-guessing logic, to find the salt for unknown versions of that protocol.
* Support for parsing and reporting fields of NetBIOS Name Service (NBNS) packets.
* Support for parsing and reporting fields of Multicast DNS (mDNS) packets.

## Version 2.5.5

* Experimental: initial pcap-ng parsing code.
* Initial microbenchmarking code to analyze pcap throughput.
* Telemetry enhancements: performance optimizations and new fields such as the libmerc version and initialization time.
* Added changes to prioritize packet filter config over STATIC_CFG_SELECT.

## Version 2.5.4

* Experimental: initial Android support for standalone mercury and cython integration.
* New option for time-based output file rotation.
* Telemetry bugfixes to address inconsistent data across telemetry files post-rotation.

## Version 2.5.3

* Added support for reading and processing different LINKTYPEs; ETHERNET, RAW (IP), and PPP are currently supported.
* Added TLS and QUIC ALPN and user-agent reporting into libmerc.h API.
* Updated IANA values and added support for Facebook’s custom versions

## Version 2.5.2
* Improved QUIC fingerprinting.
* Added support for HTTP and QUIC process identification.
* Improved HTTP process identification by incorporating the User-Agent as additional context in the classifier.
* Separated the DTLS class from the TLS class, and moved it into its own [separate header file](src/libmerc/dtls.h).

## Version 2.5.1
* Extended the `stats` feature to report HTTP and QUIC metadata data, in addition to TLS data. Refactored the message queues to use tuples to serialise/deserialisze data features.
* IPv6 addresses are now reported in compressed format in the JSON output and `stats` output.
* Added  [libmerc_api.h](src/libmerc_api.h), a header-only C++ library that provides a clean interface into `libmerc.so`, and [libmerc_util](src/libmerc_util.cc), a test/example/driver program that dynamically loads a variant of that library.

## Version 2.5.0
* Replaced resource directory with resource archive.  A single compressed archive (or `.tar.gz`) file holds all of the resources that mercury needs in order to run its classifier.  The --resources command line option now specifies the path of the resources archive.  This change makes it easier to configure and distribute the set of resource files as an atomic set.  The archive format is a conventional Unix Standard tape archive format (as defined by POSIX in IEEE P1003.1-1988, and widely used through the GNU `tar` utility), compressed with GZIP (as defined by RFC1952, and widely used through `gzip` and `pigz`).
* Added the experimental `stats` feature, which computes and stores aggregate statistics regarding TLS fingerprints and destinations, and periodically writes those statistics out to a compressed JSON file.   The stats file output is independent from the normal session-oriented JSON output.  The number of stats entries can be limited in order to protect against memory exhaustion.  This feature is currently experimental, and is likely to evolve.  It uses these new command line options:

        --stats=f                             # write stats to file f
        --stats-time=T                        # write stats every T seconds
        --stats-limit=L                       # limit stats to L entries
* Added [SMTP](src/libmerc/smtp.h) parsing.
* Gathered together most of libmerc's global variables, to enable multiple libmerc instances to be used concurrently.   This makes it possible to update libmerc by loading a newer version of limberc.so.
* Added the [libmerc_driver](src/libmerc_driver.cc) test program to test concurrent uses of libmerc.

## Version 2.4.0
* Added [batch_gcd](doc/batch-gcd.md), a program for efficiently finding the common factors of RSA public keys.
* Refactored TCP packet processing to use a C++17 `std::variant` for compile-time polymorphism, which enabled considerable code simplification.
* Added [mercury-json-validity-check.sh](test/mercury-json-validity-check.sh) to improve test coverage of mercury's different command line options.

## Version 2.3.6
* Organized all packet processing functions into [libmerc](src/libmerc), a separate library with makefile targets to support both shared objects and a static library.  An interface is defined in [libmerc.h](src/libmerc.h) (with [doxygen-based documentation](doc/mercury.pdf)), which provides a programmatic interface to TLS fingerprinting with destination context.
* Added the initial version of [tls_scanner](src/tls_scanner.cc), a tool for scanning HTTPS servers to obtain certificates, HTTP response headers, and redirect and src= links, and to test for domain fronting.
* Added [cert_analyze](src/cert_analyze.cc), a tool for analyzing X509/PKIX certificates.
* Added command completion for mercury, cert_analyze, and tls_scanner.

## Version 2.3.5
* Optimized the [Naive Bayes classifier for process and malware identification](doc/wnb.md).

## Version 2.3.4
* *Multiple* PCAP files can be piped in to the standard input, like `cat *.pcap | ./mercury`, which can simplify workflow and improve performance, especially when working with HDFS and NFS, by minimizing or eliminating the need to write intermediary files to disk.
* Added defensive coding (no changes in functionality).

## Version 2.3.3
* Improved QUIC processing.
* Added recognition of CONNECT, PUT, and HEAD methods for HTTP fingerprinting.
* Fixed a bug in the --analysis module caused when the fingerprint database contains a count field greater than 2^31.

## Version 2.3.2
* QUIC client fingerprints are now reported.
* PCAP files can be piped in to the standard input, like `cat dhcp.pcap | ./mercury --metadata`.  This feature makes it easier to work with some environments like HDFS.
* Added [documentation](doc/schema.md) for the JSON schema output by mercury.
* New **--nonselected-tcp-data** option writes out the TCP Data field for *non*-selected traffic, as a hex string in the JSON output.  This option provides a view into the TCP data that the --select option does not recognize. The --select filter affects the data written by this option; if you want to see the TCP Data field for all traffic, then '--select=none' on the command line.
* New **--nonselected-udp-data** option, similar to the one above, but for UDP traffic.
* There was a significant refactoring that eliminated much dead code, and flattened the packet-processing code (which is now in `pkt_proc.cc`, which is where you would probably expect to find it).
* Experimental suport for [on-demand TCP reassembly](doc/odtcpr.md).
* Improvements to DNS and DHCP processing and JSON output.
* Added documentation for the [safe parsing strategy](doc/safe-parsing.md) that mercury uses for parsing packets and certificates.

## Version 2.3.0
* New **--resources** command line option causes resource files (used in analysis) to be read from a directory other than the default.  This makes it easier to use a fingerprint prevalence database other than the system default one.
* New metadata output: SSH KEX INIT message and TCP initial sequence number (that is, the SEQ of the TCP SYN packet).
* The packet processing logic has been refactored to use a more systematic approach to packet parsing, which is documented in [doc/safe-parsing](https://github.com/cisco/mercury/blob/master/doc/safe-parsing.md).  The new code is considerably easier to read and extend; it is utilized by the JSON output path, though some functions from the old lower-level approach to packet parsing is still in place in the PCAP output path.

## Version 2.2.0
* New **--metadata** command line option causes JSON output to include a lot more metadata in its output: tls.client.version, tls.client.random, tls.client.session_id, tls.client.cipher_suites, tls.client.compression_methods, tls.client.server_name, tls.server.random, tls.server.certs, http.request.method, http.request.uri, http.request.protocol, http.request.host, and http.request.user_agent.
*  Accomodating the richer metadata required changes to the previous JSON schema.  The current schema is documented in [json-test.py](test/json-test.py).

## Version 2.1.0
* TLS certificates can optionally be output in detail as a JSON object, with the **--certs-json** command.
* Experimental: DNS responses can optionally be output in detail as a JSON object, with the **--dns-json** command.   The JSON schema used with this feature is likely to change.
* The --select (or -s) command now accepts an optional argument that specifies one or more protocols to select.  The argument --select=tls,dns causes mercury to process only TLS and DNS packets, for instance.
* Added support for VXLAN and MPLS
* Per-packet output is no longer supported
