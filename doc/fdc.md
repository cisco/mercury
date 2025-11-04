# Fingerprint and Destination Context (FDC) Schema



This note documents the data formats used in the Mercury Fingerprint and Destination Context (FDC).  The FDC is encoded using the Concise Binary Object Representation ([CBOR](https://datatracker.ietf.org/doc/html/rfc8949)), an IETF standard data format that is extensible, consice, and trivially mappable to the common JavaScript Object Notation ([JSON](https://datatracker.ietf.org/doc/html/rfc8259)).  The formats are formally defined using the Concise Data Definition Language ([CDDL](https://datatracker.ietf.org/doc/html/rfc8610)), an IETF standard notational convention for unamiguously expressing CBOR and JSON data formats.

A Fingerprint and Destination Context (FDC) object contains a Network Protocol Fingerprint ([NPF](https://github.com/cisco/mercury/blob/main/doc/npf.md)) and other data features, all of which are metadata observed in a single network session.  An NPF fingerprint is a set of data features formed by selecting and normalizing some elements of a protocol message, so that they are correlated with the sending application or library implementation.  A fingerprint by itself sometimes uniquely identifies an application, but often does not.   In the latter case, the other data features are valuable for indentifying the sending application.

- An NPF fingerprint in CBOR encoding, as defined in the [NPF CDDL specification](https://github.com/cisco/mercury/blob/main/doc/npf.cddl).
- The server name, which corresponds to the TLS or QUIC Server Name field or the HTTP Host field.
- The destination IP address, as a string containing a textual representation.
- The destination port number, as an unsigned integer less than 64,535.
- The user agent as a string, which corresponds to the value of the User-Agent header for HTTP, the value of the SOFTWARE attribute for STUN, and the concatenation of the Protocol and Comment strings for SSH.
- Optionally, an unsigned integer corresponding to the truncation code, which indicates whether reassembly was required in order to obtain a complete fingerprint, and whether or not the fingerprint was truncated due to a missing packet.  Its values are
  - none = 0,
  - reassembled = 1
  - truncated = 2
  - reassembled and truncated = 3.

The protocol (TLS, QUIC, HTTP, STUN, SSH) is identified by the fingerprint.

The formal CDDL defintion is as follows:

```
; fdc is a record-style array of data elements comprised of a
; fingerprint and the associated destination context.
;
fdc = [
   fingerprint,              ; as defined in npf.cddl
   str,                      ; server name
   str,                      ; destination IP address, textual representation
   uint,                     ; destination port (max: 0xffff)
   str,                      ; user agent
   ? uint                    ; truncation
]
```

​
