# Network Protocol Fingerprinting (NPF): A Flexible System for Identifying Protocol Implementations

**Pre-Publication Draft**

David McGrew
February 28, 2022



## Introduction

This draft specifies a flexible and general format for Network Protocol Fingerprints (NPF), suitable for representing fingerprints from different protocols, and capable of evolving over time to accommodate new protocol extensions and uses.  

Network protocol fingerprinting is a form of pattern recognition that aims to identify a particular implementation protocol from the messages that it sends.   In this note, a fingerprint is a byte string formed from substrings of that message.   This string-oriented approach generalizes across different protocols.  More complex approaches, such as machine learning, are out of scope, though fingerprint strings can be used as a data feature in such systems.  This note provides background, a specification of how to construct and interpret NPF fingerprints, and fingerprint rules for TLS, QUIC, and other protocols. 

In this note, a fingerprint is a summarization of a packet that is characteristic of one or more implementations.  Selected bytes from the packet are copied into a fingerprint, after being normalized.  Each fingerprint type defines the byte strings that are extracted from the packet and how they are normalized.

A fingerprint is formally defined as an ordered, multi-way tree of byte strings, where the tree corresponds to a parsing of a packet.  Balanced parenthesis are used to represent the tree structure, and hexadecimal is used to represent the byte strings.  Whenever possible, the byte substrings in the fingerprint correspond directly to byte substrings of the packet, to preserve information, and to aid implementation and debugging.  While it is necessary to define fingerprints in terms of protocol specifications,  this note aims to minimize dependencies on externally defined data formats.

## Definitions and Notation

A byte is an unsigned integer between 0 and 255, inclusive, usually represented in hexadecimal.  Byte strings are indexed starting at zero.  A byte string *s* of length *n* consists of bytes *s*[0], *s*[1], ... , *s*[n-1].  Byte strings are written in hexadecimal, and always contain an even number of hex characters.

When *s* is a byte string, *s*[*i:j*] denotes the substring of s consisting of bytes *i*, *i*+1, ..., *j*-1, inclusive.  The index *j* must be no greater than the length of *s*, or the expression is undefined.

When a byte string appears in a fingerprint, it is surrounded by parenthesis, such as `(0303)`, to delimit where it begins and ends.  A list of byte strings is denoted by surrounding an ordered sequence of strings with parenthesis, such as `((04)(08)(01)(030307))` .  A sorted list of bytes strings is denoted by surrounding a sorted sequence of bytes strings with square braces, such as `[(01)(030307)(04)(08)]`.  Sorting is performed lexicographically (e.g. as with the C `memcmp()` function), and is used in some fingerprints to normalize data.

Contiguous sequences of similarly encoded elements, such as TCP Options or TLS Extensions, appear in many protocols, and are important in fingerprinting.  In NPF, those sequences are processed by handling each element in the sequence in the same way, and in the same order in which they appear in the packet.  This results in a (possibly sorted) list of strings, one for each element.

A list, or a sorted list, may contain another list, or sorted list, as an element.  For example, `((ffa5)[(04)(05)(06)(07)(09)(0e)(0f)])` is a list consisting of the string `(ffa5)` followed by the sorted list `[(04)(05)(06)(07)(09)(0e)(0f)]`.

The *string representation* of a fingerprint is a printable string containing one or more elements, each of which is either a string, list, or sorted list.  The *hash representation* (see below) is computed by applying a cryptographic hash to this string.

### Functions

Some fingerprint definitions make use of functions.  The function `MAP` takes as input a string S, an integer N, and a function F that accepts an N-byte string and returns another string, and returns the string formed by breaking S into N-byte values, applying F to each value, and concatenating the results.   For instance, given the function ODD defined by

    ODD(x) = 0x01 if x is an odd number, and 0x00 otherwise,

and the string S = (0001020304050607), then

    MAP(S, 1, ODD) = (0001000100010001).

### Sets

Fingerprint normalization may involve a check to see if a substring from a packet is an element of a particular set of strings.  Sets are denoted in C-style syntax, as a comma-separated sequence of hexadecimal strings.  For instance, the set

```
EXAMPLE_SET = {
    0x02, 0x03
}
```

denotes the set { 0x02, 0x03 }.

### Hash Representation

The hashed representation of a fingerprint is computed by applying SHA-256 to its string representation, then encoding the output of that function as a 32-character hexadecimal string.  This representation is shorter than the string representation, has a fixed length, and does not include any punctuation.  This makes it easier to incorporate into database schemas, and easier for human operators to compare and cut-and-paste values between software tools.

The hash representation is not reversible, and it only supports exact matching, not approximate matching or prefix matching.  It should be only used as a nickname for the full representation.  

A hash representation can easily be distinguished from a string representation, as the latter always starts with an opening parenthesis character '(', while the former never does.



## Naming and URIs

Fingerprint rules and fingerprints are named using Uniform Resource Indicators (URIs, [RFC 3986](https://datatracker.ietf.org/doc/html/rfc3986)) in the Network Protocol Fingerprinting (NPF) scheme.  For example, a fingerprint with the hash of `cfb2a31d1f2142e5c163a5892e696334` that is computed using the rule `tls` defined by `npf.io` is represented as

 `npf:npf.io/tls/cfb2a31d1f2142e5c163a5892e696334`.

A fingerprint name is **fully qualified** if it includes a specification, a rule, and either a hash value or a string representation.

NPF URIs can be used as components of HTTPS URIs; for instance, https://npf.io/tls/r1/cfb2a31d1f2142e5c163a5892e696334 can represent a resource with information about that fingerprint.  

The NPF URI scheme is formally defined as follows:

- The scheme identifier string is`npf`.
- The authority string should be a valid HTTPS authority, but can be any string matching `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`.
- The path consists of a rule identifier, a forward slash '/', and then a string representation or a hash representation.



## TCP/IP

The TCP/IP fingerprint is formed from TCP/IP SYN packets, that is, packets that contain a valid IP header, a valid TCP header, and have the TCP SYN flag set (but not the TCP ACK flag set).  The fingerprint format is 

```
    "tcp/" (IP_Version)(IP_ID)(IP_TTL)(TCP_Window)((TCP_Option)*)
```

Where the elements are defined as follows:

- `IP_Version` (string, one byte) represents the IP Version field (RFC 791) in its most significant four bits, and zero in its least significant four bits.  Its value is 0x40 or 0x60 for IPv4 and IPv6, respectively.   It can be computed as the logical AND of the first byte of the IP header and the value 0xf0.

- `IP_ID` (string, variable length) represents the IP ID field for IPv4, and the Flow Label field for IPv6; note that the former is two bytes long, and the latter is 20 bits long.  If that field is zero, then the IP_ID field is 00; otherwise, it is empty.
- `IP_TTL` (string, one byte) represents the value of the TTL field bitwise ORed with 0xe0.  The resulting value will be a multiple of 32 (decimal).  For instance, it will be 0x00 if the TTL is less than 32 (decimal), 0x20 if the TTL is between 33 and 64 (decimal), and so on.
- `TCP_Window` (string, two bytes) is the TCP Window field (RFC 793).
- `TCP_Option` (sequence, variable length) elements represent the TCP Option fields (RFC 793), a variable-length sequence of variable-length options that appears at the end of a TCP header.  Let `option` denote the byte string consisting of a TCP Option on the wire.  Then the corresponding `TCP_Option` element in the fingerprint is defined as

```
   TCP_Option = option    if option[0] is in TCP_OPT_FIXED, and
                option[0] otherwise.
```

where

 the set `TCP_OPT_FIXED = { 0x02, 0x03 }`.

**DESIGN QUESTION:** do we want SYN/ACK fingerprints?  Should we include those flags in the fingerprint, so that we can distinguish them?


----

## TLS

TLS fingerprints are formed from packets containing a TLS Client Hello message.  The TLS fingerprint format is

```
   "tls/" (TLS_Version) (TLS_Ciphersuite) ((TLS_Extension)*)
```

where

- TLS_Version (string, two bytes) represents the TLSPlaintext.legacy_record_version field from the TLS record (RFC 8446, Section 5.1).

- TLS_Ciphersuite (string, variable length) is computed from the array of CipherSuites from the ClientHello.cipher_suites variable-length vector, not including the length field (RFC 8446, Section 4.1.2).  Let ciphersuite_array denote that field; then TLS_Ciphersuite is computed as

      MAP(ciphersuite_array, 2, DEGREASE).

- TLS_Extension (sequence, variable length) elements represent TLS Extension fields as defined in RFC 8446, Section 4.2.  Let extension denote the byte string consisting of a TLS Extension in the packet.  Then the corresponding TLS_Extension element in the fingerprint is defined as


```
  TLS_Extension = extension                if DEGREASE(extension[0:2]) is in TLS_EXT_FIXED, and
                  DEGREASE(extension[0:2]) otherwise.
```

   The function DEGREASE takes as input a two-byte value and returns a two-byte value.

```
   DEGREASE(x) = 0x0a0a if x is in TLS_GREASE, and
                 x      otherwise.
```

The sets TLS_GREASE and TLS_EXT_FIXED are defined as    

```
TLS_GREASE = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
}

TLS_EXT_FIXED = {
    0x0001, 0x0005, 0x0007, 0x0008, 0x0009, 0x000a, 0x000b, 0x000d,
    0x000f, 0x0010, 0x0011, 0x0018, 0x001b, 0x001c, 0x002b, 0x002d,
    0x0032, 0x5500
}.
```





## QUIC

QIUC fingerprints are computed from the QUIC Initial Packet.   To compute this fingerprint, it is necessary to remove header protection, decrypt the QUIC Frames, reassemble the CRYPTO Frame, and then process the TLS Client Hello in that frame.  If there is no CRYPTO Frame in the packet, it is not possible to compute a fingerprint.  The fingerprint format is 

```
"quic/" (QUIC_Version) (TLS_Version) (TLS_Ciphersuites) [ QUIC_Extension* ]
```

 where 

- `QUIC_Version` (string, four bytes) is the Version field from the QUIC long header form.

- `TLS_Version` and `TLS_Ciphersuites` are as defined in the TLS section.  They are computed from the TLS Client Hello reassembled from the CRYPTO Frame in the decrypted QUIC initial packet.  

- `QUIC_Extension` (sequence, variable length) elements represent TLS Extension fields as defined in RFC 8446, Section 4.2.  Let `extension` denote the byte string consisting of a TLS Extension in the Client Hello reassembled from the CRYPTO frames.  Then the corresponding `QUIC_Extension` element in the fingerprint is defined as

```
QUIC_Extension = extension                 if DEGREASE(extension[0:2]) is in TLS_EXT_FIXED, 
                 QTP(extension)            if extension[0:2] is in { 0x0039, 0xffa5 },
                 DEGREASE(extension[0:2])  otherwise.
```

The function `QTP` computes a sorted list of elements from the QUIC Transport Parameters Extension,  as below:

```
QTP(extension) = (extension[0:2])  [  (QUIC_DEGREASE(Transport_Parameter_ID))* ] 
```

Here Transport_Parameter_ID is the variable_length_integer that represents the ID of the Transport Parameter (as defined in RFC 9000, Section 18).   The function QUIC_DEGREASE takes as input a variable_length_integer *x* and returns a byte string; if *x* % 31 == 27, the value of 0x1b is returned; otherwise, *x* is returned.

An example of a QUIC fingerprint is

```
quic/(ff00001d)(0303)(0a0a130113021303)[(0a0a)(0a0a)(0000)(000500050100000000)(000a000c000a0a0a001d001700180019)(000d0018001604030804040105030203080508050501080606010201)(0010000e000c0568332d32390568332d3237)(0012)(001b0003020001)(002b0005040a0a0304)(002d00020101)(0033)((ffa5)[(04)(05)(06)(07)(09)(0e)(0f)])]
```



## HTTP

HTTP fingerprints are computed from HTTP request packets, for HTTP version 1.1 ([RFC 7230](https://datatracker.ietf.org/doc/html/rfc7230#section-3), Section 3).  The fingerprint format is 

```
"http/" (method) (request-target) (version) ((selected-header)*)
```

where

- `method` (string, variable length) is the first token in the request-line (e.g. GET, POST, etc.),
- `request-target` (string, variable length) is the second token in the request line, which is derived from the Uniform Resource Indicator (URI),
- `version` (string, variable length) is the last token in the request line.
- The `selected-header` (sequence, variable length) elements represent successive headers in the request.  Each header has the form  `header = field-name ": " field-value `, where ": " is a literal string consisting of the ASCII characters with codes 0x3a and 0x20, and `field-name` and `field-value` are tokens, as per ([RFC 7230](https://datatracker.ietf.org/doc/html/rfc7230#section-3.2), Section 3.2).  The `selected-header` fields corresponding to the headers in the request are defined as


```
  selected-header = header           if TOLOWER(field-name) is in HTTP_REQUEST_NAME_AND_VALUE, else
                    field-name       if TOLOWER(field-name) is in HTTP_REQUEST_NAME_ONLY.
```

Note that no case transformation is performed on the field-name that is included in the fingerprint, though the comparison function used in the selected-header logic does process that field in a case-insensitive way.  The function TOLOWER is defined by

    TOLOWER(S) = MAP(S, 1, CHAR_TOLOWER)

where CHAR_TOLOWER(x) takes a single byte as input and returns a single byte, and is defined as


```
CHAR_TOLOWER(x) = x  	      if x < 0x41 or x > 0x5a, 
                  x | 0x20    otherwise.
```

For instance, `TOLOWER("Host:") = "host:"`.

The sets HTTP_REQUEST_NAME_AND_VALUE and HTTP_REQUEST_NAME_ONLY are defined as    

```
HTTP_REQUEST_NAME_AND_VALUE = {
    "accept"
    "accept-encoding",
    "connection",
    "dnt",
    "dpr",
    "upgrade-insecure-requests",
    "x-requested-with"
}

HTTP_REQUEST_NAME_ONLY = {
    "accept-charset",
    "accept-language",
    "authorization",
    "cache-control",
    "host",
    "if-modified-since",
    "keep-alive",
    "user-agent", 
    "x-flash-version",
    "x-p2p-peerdist"
}.
```



## DTLS

*TBD*



## DHCP

*TBD*

​	

#### Truncated Fingerprints

A truncated fingerprint, formed from a truncated PDE, may be analyzed using prefix matching, but should not be analyzed using exact matching.   

*Not yet implemented*: if a fingerprint is truncated, then each truncated field is closed with a different character than `)`.

### Matching

There are several ways that a PDE can match a fingerprint:

- an *exact match* occurs when each normalized data element computed from a PDE exactly matches the corresponding data element of the fingerprint
- a *prefix match* occurs when each normalized data element computed from a (possibly truncated) PDE matches the corresponding data element in a fingerprint
- an *approximate match* occurs when the edit distance between the normalized data elements computed from a PDE and those of a fingerprint and lower than the edit distance to all other fingerprints.



## Background and Motivation

Several network fingerprinting systems are in use to recognize clients, servers, and operating systems, including [P0F](https://lcamtuf.coredump.cx/p0f3/), [nmap](https://nmap.org/book/man-os-detection.html), [JA3](https://github.com/salesforce/ja3), and [mercury](https://github.com/cisco/mercury).  NPF aims to incorporate their best practices, and provide additional flexibility.  In order for a fingerprint system to be able to evolve, it must be able to recognize new protocol data elements and include them in its format.   To correctly interpret a fingerprint, a user must know the rules used in forming it.  

NPF's goals are:

- to enable fingerprint systems to accommodate new protocol extensions and new protocol behaviors, while at the same time being backwards compatible with fingerprints generated according to older specifications, 
- to make it easier to share and automatically process fingerprint data, by explicitly including metadata about protocols and specifying versions in the fingerprint identifiers,
- to support partial matching as well as exact matching, and
- to facilitate interoperability and exchange between different fingerprinting systems.

A secondary goal is to handle fingerprints generated from truncated packets, which can be caused by the loss of a packet carrying a segment of a data element.  







## Comparison to Existing Fingerprinting Systems

The JA3 fingerprinting system has a relatively compact representation, consisting of 32 hex characters, but it only applies to TLS, is not reversible, and does not utilize GREASE information.  The mercury fingerprinting system is reversible, utilizes GREASE, and applies to multiple protocols, but it does not contain an explicit indication of the protocol, and is not compact.  Neither system allows to indicate versioning information that would enable the details of the fingerprinting scheme to adapt over time.  This note defines a fingerprint naming scheme that aims to provide the benefits of both systems, along with explicit information about protocols and versions, drawing inspiration from the Common Platform Enumeration (CPE) naming system [1]. 



## Appendix A: JA3

Computing JA3 Fingerprints (following https://github.com/salesforce/ja3)

JA3 gathers the decimal values of the bytes for the following fields in the Client Hello packet; SSL Version, Accepted Ciphers, List of Extensions, Elliptic Curves, and Elliptic Curve Formats. It then concatenates those values together in order, using a "," to delimit
each field and a "-" to delimit each value in each field.

The field order is as follows:

SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat

Example:

`769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0`

If there are no SSL Extensions in the Client Hello, the fields are left empty.

Example:

`769,4-5-10-9-100-98-3-6-19-18-99,,,`

These strings are then MD5 hashed to produce an easily consumable and
shareable 32 character fingerprint. This is the JA3 SSL Client
Fingerprint.

769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0 --> ada70206e40642a3e4461f35503241d5

769,4-5-10-9-100-98-3-6-19-18-99,,, --> de350869b8c85de67a350c8d186f11e6

We also needed to introduce some code to account for Google’s GREASE (Generate Random Extensions And Sustain Extensibility) as described here. Google uses this as a mechanism to prevent extensibility failures in the TLS ecosystem. JA3 ignores these values completely to ensure that programs utilizing GREASE can still be identified with a single JA3 hash.



## References

[1] Brant A. Cheikes, David Waltermire, Karen Scarfone, NIST Interagency Report 7695, Common Platform Enumeration: Naming
    Specification Version 2.3, August 2011.

[2] Fingerprinting with JA3 and JA3S, https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967

[3] https://github.com/cisco/mercury

[4] Blake Anderson and David McGrew, Accurate TLS Fingerprinting using Destination Context and Knowledge Bases, 2020, https://arxiv.org/abs/2009.01939.

