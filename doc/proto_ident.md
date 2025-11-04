Protocol Identification Using Bitmasks and Trial Parsing

Traditionally, network protocols could be identified based on their
use of registered TCP or UDP destination ports (IANA Port
Registry)[https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml]
but this is not longer true.  To paraphrase IANA, firewall and system
administrators need to consider the actual traffic in question, and
not rely on its port number, whether it is registered or not.

To extract metadata from a traffic stream, we need to identify
particular Protocol Data Units (PDUs), such as TLS client hello
messages, or SMTP HELO or EHLO requests.  This is a slightly different
problem than protocol identification.  Metadata extraction sometimes
reveals more interesting information, for instance, when a session
starts out as SMTP then switches to TLS via STARTTLS.

To identify a PDU without using port numbers, it is necessary to
analyze the TCP or UDP Data field.  So the PDU identification problem
consists of analyzing a data field and determining what PDU, if any,
it matches.  In C/C++ notation, we have a function

```
   bool match(const uint8_t *data, size_t length);
```

that returns `true` when the byte string of a valid PDU is input, and
`false` otherwise.  We define a *false negative* as when a valid PDU
is input and `match` returns `false`, and a *false positive* as when a
non-valid PDU is input and `match` returns `true`.  In some settings,
it is desirable to avoid false negatives, even if this means
tolerating more false positives.  Many protocol implementations are
not consistent with standards, so a PDU matcher probably wants to
follow Postel's robustness principle
(RFC761)[https://datatracker.ietf.org/doc/html/rfc761#section-2.10]
and be liberal in what they accept.

Besides minimizing the number of false positives and false negatives,
we also need to minimize the computational cost.  The dominant cost is
the computation needed to reject an invalid byte string.

A further complication is the fact that, when we consider multiple PDU
types from different protocols, it may be the case that a byte string
is a valid for more than one PDU type.  This is especially true for
encrypted formats.

Mercury uses two techniques to identify PDUs.  First, the data field
is checked to see its initial bytes have a bit pattern that is
consistent with the PDU.  If it is, then analysis proceeds to a second
stage, where a parse of the data field will be attempted.  The parse
aims to be lightweight; it verifies the format, and identifies the
location within the packet of the important data elements, but it does
no other processing.  During the first stage, if the byte string does
not match the PDU's bit pattern, the matcher returns immediately with
a `false`.


Mercury looks for bit patterns using a bitmask and and expected value.
A good example of how this works is that of the TLS Client Hello
message.  The first six bytes of that Protocol Data Unit (PDU) appear
at the start of the TCP Data field in each new TLS session.  The
values of those bytes for versions 1.0 through 1.3 of that protocol
are

```
   16 03 01  *  * 01   data (for TLSv1.0)
   16 03 02  *  * 01   data (for TLSv1.1)
   16 03 03  *  * 01   data (for TLSv1.2)
   16 03 03  *  * 01   data (for TLSv1.3)
   ---------------------------------------
   ff ff fc 00 00 ff   mask
   16 03 00 00 00 01   value = data & mask
```

... where each byte is shown in hexadecimal.  The mask and value at
the bottom of the figure are byte strings that can be used to identify
when a data field holds that PDU, because the identity

```
   data & mask = value
```

always holds.

The program `string`, with the option `--find-mask`, can be used to find
a bitmask and corresponding value that matches a set of strings.
