On-Demand TCP Reassembly

Many interesting network data features may be fragmented across two or
more TCP segments.  Before processing these data features, it is
necessary to to reassemble the corresponding TCP segments.  However,
it is computationally expensive to reassemble an entire TCP stream, so
mercury uses an on-demand approach.  A function parsing a TCP data
field can request reassembly of a particular segement of the TCP data
stream.  A *reassembler* handles these requests.  A request consists
of the initial sequence number of the segment, and the number of bytes
in the segment.  A request can also include the first N bytes of the
segment.

The format of TLS records and SSH binary packets explicitly contains
an indication of the length of those elements.  If, while parsing one
of those elements, the length of the element exceeds the length of the
packet, a reassembly request can be created.  Since the length of the
data element is known, the length of the TCP segment is known, and the
reassembler knows exactly what TCP sequence number to look for.

HTTP 1.1 does not contain such an indication.  A request to reassemble
this protocol can ask for the remainder of the TCP message; the
reassembler can use "nonincrementing ACK" definition of TCP messages.
That definition works whenever the communication is synchronous, as is
the case for HTTP 1.1.

Packet loss may prevent the reassembly process from being completed.
To handle these "zombie" cases, the reassembler needs a mechanism to
detect them, and a mechanism to process the incomplete messages.
Detection can be accomplished by maintaining, along with each segment,
a timestamp of when it was created.  A "reaper" function can traverse
this list, process the incomplete segments, and then delete them.

To avoid memory allocation, a preallocated array of segments is used.
To better accomodate different segment sizes, the reassembler could
use a big array of short segments and a short array of long segments.

Performance issues: storage and caching.

