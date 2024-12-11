# Network Protocol Fingerprinting (NPF): A Flexible System for Identifying Protocol Implementations

**Draft**

David McGrew (Editor)




## Introduction

This note specifies a flexible and general format for Network Protocol Fingerprints (NPF), suitable for representing fingerprints from different protocols, and capable of evolving over time to accommodate new protocol extensions and uses.  It provides background, a specification of how to construct and interpret NPF fingerprints for TLS, QUIC, and other protocols, and a naming scheme that indicates the protocol and rules used in fingerprint construction.

Network protocol fingerprinting is a form of pattern recognition that aims to identify a particular implementation of a protocol from the messages that it sends.   In this note, a fingerprint is a set of data features formed by selecting and normalizing some elements of a protocol message, which can be serialized into a string.  An implementation can be a library, an application, or an operating system.  In general, a single fingerprint may match more than one application, especially when the implementation is a library.  A single application can also produce more than one fingerprint.

A fingerprint is formally defined as an ordered, multi-way tree of byte strings; the tree structure is used to represent the strings yielded by parsing a protocol message.  Balanced parenthesis are used to represent the tree structure, and hexadecimal is used to represent the byte strings.  Whenever possible, the byte substrings in the fingerprint correspond directly to byte substrings of the packet, to preserve information, and to aid implementation and debugging.  While it is necessary to define fingerprints in terms of protocol specifications,  this note aims to minimize dependencies on externally defined data formats.

### Matching

There are several ways that a protocol message can match a fingerprint:

- an *exact match* occurs when each normalized data element computed from a message exactly matches the corresponding data element of the fingerprint,
- a *prefix match* occurs when each normalized data element computed from a (possibly truncated) message matches the corresponding data element in a fingerprint, and
- an *approximate match* occurs when the edit distance between the normalized data elements computed from a message and those of a fingerprint and lower than the edit distance to all other fingerprints.

Exact matching is straightforward; a fingerprint constructed from a message can be compared against a (potentially large) set of fingerprints by using a hash table.  There are multiple ways that approximate matching and prefix matching can be done.  None are specified in this note, but the string representation provides enough information to facilitate either method.

 A fingerprint can be used directly, or can be used along with other data features in a more in-depth analysis.

## Definitions and Notation

A byte is an unsigned integer between 0 and 255, inclusive.  Byte values are written in hexadecimal, and always contain an even number of hex characters.  A byte string is a sequence of zero or more bytes, indexed starting at zero.  The bytes in a string *s* of length *n* are denoted as *s*[0], *s*[1], ... , *s*[n-1].  When *s* is a byte string, *s*[*i:j*] denotes the substring of s consisting of bytes *i*, *i*+1, ..., *j*-1, inclusive.  The index *j* must be no greater than the length of *s*, or the expression is undefined.

When a byte string appears in a fingerprint, it is surrounded by parenthesis, such as `(0303)`, to delimit where it begins and ends.  A list of byte strings is denoted by surrounding an ordered sequence of strings with parenthesis, such as `((04)(08)(01)(030307))` .  A sorted list of bytes strings is denoted by surrounding a sorted sequence of bytes strings with square braces, such as `[(01)(030307)(04)(08)]`.  Sorting is performed lexicographically (e.g. as with the C `strcmp()` function), and is used in some fingerprint formats to normalize data.

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

The hashed representation of a fingerprint is computed by applying [SHA-256](https://www.rfc-editor.org/rfc/rfc6234) to its string representation, then encoding the output of that function as a 32-character hexadecimal string.  This representation is shorter than the string representation, has a fixed length, and does not include any punctuation.  This makes it easier to incorporate into database schemas, and easier for human operators to compare and cut-and-paste values between software tools.  It is cryptographically infeasible to find two distinct SHA-256 inputs that produce the same hash value, [unlike MD5](https://www.rfc-editor.org/rfc/rfc6151).

The hash representation is not reversible, and it only supports exact matching, not approximate matching or prefix matching.  It should be only used as a nickname for the full representation, and not a replacement for it.

Within a fingerprint string, a hash representation can easily be distinguished from a string representation, as the latter always starts with an opening parenthesis character '(', while the former never does.



## Naming and URIs

Fingerprints are named using [Uniform Resource Indicators](https://datatracker.ietf.org/doc/html/rfc3986) (URIs) in the Network Protocol Fingerprinting (NPF) scheme, which is formally defined as follows:

- The scheme identifier string is`npf`.
- The path consists of a protocol identification string (e.g. `tls`), a forward slash '/', an optional rule identifier string (e.g. '1') followed by a forward slash '/', and then a string representation or a hash representation.  Version strings SHOULD be positive decimal numbers.
- The optional authority string should be a valid HTTPS authority, but can be any string matching `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )`.

An example of a minimal fingerprint is the following QUIC fingerprint, which contains only a protocol identifier and a string representation:

```
quic/(ff00001d)(0303)(0a0a130113021303)[(0a0a)(0a0a)(0000)(000500050100000000)(000a000c000a0a0a001d001700180019)(000d0018001604030804040105030203080508050501080606010201)(0010000e000c0568332d32390568332d3237)(0012)(001b0003020001)(002b0005040a0a0304)(002d00020101)(0033)((ffa5)[(04)(05)(06)(07)(09)(0e)(0f)])]
```

An example of a `tls` fingerprint with the hash representation of `cfb2a31d1f2142e5c163a5892e696334` that is computed using a format defined by the authority `npf.io` is

```
npf://npf.io/tls/cfb2a31d1f2142e5c163a5892e696334
```

This naming scheme allows different authorities to define their own formats (e.g. data feature selection and normalization rules).  However, those definitions [SHOULD](https://www.rfc-editor.org/rfc/rfc2119.html) use the data feature definitions in this note whenever possible, or should aim for consistency.



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




----

## TLS

TLS fingerprints are formed from packets containing a TLS Client Hello message.  There are three fingerprint formats defined. The format "tls/1", sorts the extensions into lexicographic order, to compensate for the randomization of those fields introduced by some TLS clients.  The recent format "tls/2" sort only the selected extensions in lexicographic order. The older one, "tls", does not sort those extensions into order.

The "tls/2" fingerprint format is
```
   "tls/2" (TLS_Version) (TLS_Ciphersuite) [(selected_TLS_Extension)*]
```

The "tls/1" fingerprint format is

```
   "tls/1" (TLS_Version) (TLS_Ciphersuite) [ TLS_Extension* ]
```

and the older "tls" fingerprint format is

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

selected_TLS_Extension chooses only a subset of extensions from TLS_extension as defined below,

```
  selected_TLS_Extension = extension                if DEGREASE(extension[0:2]) is in TLS_EXT_FIXED,
                           ENCODE(extension[0:2])   if ENCODE(extension[0:2]) is in TLS_EXT_INCLUDE,
```

The function ENCODE is defined as below
```
ENCODE(x) = DEGREASE(x) if DEGREASE(x) is in TLS_EXT_INCLUDE
            ENCODE_UNASSIGNED(x) if x is in TLS_UNASSIGNED
            ENCODE_PRIVATE(x) if x is in TLS_PRIVATE

```

The function ENCODE_UNASSIGNED and ENCODE_PRIVATE accepts a 2 byte value and returns a two byte value and is defined as below,

```
ENCODE_UNASSIGNED(x) = 0x003e    if x is in TLS_UNASSIGNED,
                       x         otherwise
```

```
ENCODE_PRIVATE(x) = 0xff00     if x is in TLS_PRIVATE,
                    x          otherwise
```

The set TLS_EXT_INCLUDE, TLS_UNASSIGNEDm TLS_PRIVATE is defined as

```
TLS_EXT_INCLUDE = {
    0x0000, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007,
    0x0008, 0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x000e, 0x000f
    0x0010, 0x0011, 0x0012, 0x0013, 0x0014, 0x0016, 0x0017, 0x0018,
    0x0019, 0x001a, 0x001b, 0x001c, 0x001d, 0x001e, 0x001f, 0x0020,
    0x0021, 0x0022, 0x0024, 0x0025, 0x0026, 0x0027, 0x0028, 0x002b,
    0x002c, 0x002d, 0x002e, 0x002f, 0x0030, 0x0031, 0x0032, 0x0033,
    0x0034, 0x0035, 0x0036, 0x0037, 0x0038, 0x0039, 0x003a, 0x003b,
    0x003c, 0x003d, 0x003e, 0x0a0a, 0x3374, 0x5500, 0x754f, 0x7550,
    0xfd00, 0xfe0d, 0xff00, 0xff01, 0xff03, 0xffa5, 0xffce
}

TLS_UNASSIGNED = set of all extensions under the category "Unassigned" as per IANA

TLS_PRIVATE    = set of all extensions under the category "Reserved for Private Use" as per IANA
```



## QUIC

QIUC fingerprints are computed from the QUIC Initial Packet.   To compute this fingerprint, it is necessary to remove header protection, decrypt the QUIC Frames, reassemble the CRYPTO Frame, and then process the TLS Client Hello in that frame.  If there is no CRYPTO Frame in the packet, it is not possible to compute a fingerprint.  There are two quic fingerprint formats. The newer format "quic/1" sorts the selected extensions in lexicographic order while the older format "quic" sorts all extensions in lexicographic order.

The "quic/1" format is

```
"quic/1" (QUIC_Version) (TLS_Version) (TLS_Ciphersuites) [(Selected_QUIC_Extension)* ]
```

The older format "quic" is

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
- `Selected_QUIC_Extension` chooses only a subset of Quic Extensions and is defined as below

```
Selected_QUIC_Extension = extension               if DEGREASE(extension[0:2]) is in TLS_EXT_FIXED,
                          QTP(extension)          if extension[0:2] is in { 0x0039, 0xffa5 },
                          ENCODE(extension[0:2])  if ENCODE(extension[0:2]) is in TLS_EXT_INCLUDE,
```


## HTTP

HTTP fingerprints are computed from HTTP request packets, for HTTP version 1.1 ([RFC 7230](https://datatracker.ietf.org/doc/html/rfc7230#section-3), Section 3) or earlier.  The fingerprint format is

```
"http/" (method) (version) ((selected-header)*)
```

where

- `method` (string, variable length) is the first token in the request-line (e.g. "GET"),
- `version` (string, variable length) is the last token in the request line (e.g. "HTTP/1.1"),
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


## OPENVPN

OPENVPN fingerprints are computed from the OPENVPN Initial Packet which also contains the TLS Client Hello.   To compute this fingerprint, it is necessary to parse OPENVPN packets (which may be more than one), reassemble the data, and then process the TLS Client Hello in the reassembled data.  If there is no TLS Client Hello in the packets, it is not possible to compute a fingerprint.  The fingerprint format is

```
"openvpn/" (ip_proto) (num_pkt) ({opcode}{key_id}) (HMAC_len) (TLS_Ciphersuites) ((TLS_Extension)*)
```

 where

- `ip_proto` (string, one byte) is the IP protocol type - 6:TCP, 11:UDP, depending on the transport protocol used for OPENVPN,

- `num_pkt` (string, one byte) is the number of OPENVPN packets across which the TLS Client Hello is split,

- `op_code` (string, one byte) is the OPENVPN packet op_code for ex 0x04 for P_CONTROL_V1,

- `key_id` (string, one byte) is the normalised key_id where the normalisation is 0x00 for key_id==0 and 0x01 otherwise,

- `{opcode}{key_id}` (string, two bytes) is the above {op_code} and {key_id} concatenated,

- `HMAC_len` (string, 1 byte) is the length of HMAC used (e.g 20 for SHA1, 32 for SHA256) if OPENVPN tls-auth is enabled or 0 otherwise,

- `TLS_Version`, `TLS_Ciphersuites`, `TLS_Extension` are as defined in the TLS section.  They are computed from the TLS Client Hello reassembled from the OPENVPN packets.

An example of a OPENVPN fingerprint is

```
openvpn/(06)(03)(0400)(14)(0301)(c014c00ac022c0210039003800880087c00fc00500350084c012c008c01cc01b00160013c00dc003000ac013c009c01fc01e00330032009a009900450044c00ec004002f00960041c011c007c00cc002000500040015001200090014001100080006000300ff)((000b000403000102)(000a00340032000e000d0019000b000c00180009000a00160017000800060007001400150004000500120013000100020003000f00100011)(0023)(000f000101))
```

## STUN

The STUN fingerprint is formed from the messages of the "classic STUN" (RFC 3489) or modern STUN (RFC 8489) protocol.  The fingerprint format is
```
    "stun/1/" (class)(method)(magic)((attribute)*)
```
where the elements are defined as
- `class` (string, one byte) is the (RFC 8489) class field
- `method` (string, two bytes) is the (RFC 8489) method field
- `magic` (string, one byte) is 01 if the Magic Cookie is present, and 00 otherwise.   The former indicates modern STUN, the latter classic STUN.
- `attribute` (string, variable length) contains the type field, and optionally the length and data fields, of an attribute, in the order that they appear in the message.  The attribute types included in this field, and the extent of the data included, are as per the following table:
```
   USERNAME                  type
   MESSAGE_INTEGRITY         type
   XOR_MAPPED_ADDRESS        type
   0x8007                    type
   MS_VERSION                type
   SOFTWARE                  type
   FINGERPRINT               type
   MS_APP_ID                 type_length_data
   MS_IMPLEMENTATION_VERSION type_length_data
   0xc003                    type
   GOOG_NETWORK_INFO         type
   0xdaba                    type
```



#### Truncated Fingerprints

A truncated fingerprint, formed from a truncated message, may be analyzed using prefix matching, but should not be analyzed using exact matching.



## Background and Motivation

Several network fingerprinting systems are in use to recognize clients, servers, and operating systems, including [P0F](https://lcamtuf.coredump.cx/p0f3/), [nmap](https://nmap.org/book/man-os-detection.html), [JA3](https://github.com/salesforce/ja3), and [mercury](https://github.com/cisco/mercury).  NPF aims to incorporate their best practices, and provide additional flexibility.  Its goals are:

- to enable fingerprint systems to accommodate new protocol extensions and new protocol behaviors, while at the same time being backwards compatible with fingerprints generated according to older specifications,
- to make it easier to share and automatically process fingerprint data, by explicitly indicating the protocol and the format (selection and normalization rules) fingerprint string,
- to support approximate and partial matching as well as exact matching,
- to provide an optional compact representation with a cryptographically collision-resistant hash function, and
- to facilitate interoperability and exchange between different fingerprinting systems.

A secondary goal is to handle fingerprints generated from truncated protocol messages, which can be caused by the loss of a packet carrying a segment of a data element.



## Comparison to Existing Fingerprinting Systems

The JA3 fingerprinting system has a relatively compact representation, consisting of 32 hex characters, but it only applies to TLS, is not reversible, and does not utilize GREASE information.  The original mercury fingerprinting system is reversible, utilizes GREASE, and applies to multiple protocols, but it does not contain an explicit indication of the protocol, and is not compact.  Neither system allows to indicate versioning information that would enable the details of the fingerprinting scheme to adapt over time.  This note defines a fingerprint naming scheme that aims to provide the benefits of both systems, along with explicit information about protocols and versions, drawing inspiration from the [Common Platform Enumeration](https://nvd.nist.gov/products/cpe) naming system.



