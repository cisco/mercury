## On-Demand TCP Reassembly
#### David McGrew, September 24, 2020

Many interesting network data features may be fragmented across two or
more TCP segments.  Before processing these data features, it is
necessary to to reassemble the corresponding TCP segments.  However,
reassembling an entire TCP stream is computationally expensive, so
mercury uses an on-demand approach: a function parsing a TCP data
field can request the reassembly of a particular segement of the TCP data
stream.  A *reassembler* handles these requests.  It provides
functions to request the reassembly of a segment, and a function to
checks a TCP packet to see if it contains part of a segment that is
currently being reassembled.  There are two types of requests, one
for when the length of the segment is known in advance, and one for
when it is not.  In the latter case, the length of the segment is
inferred from the TCP ACK field; this method is called TCP 
message reassembly, and it works whenever the communication
is synchronous (that is, the client and server take turns talking
and listening, and never talk at the same time).  In mercury, this
functionality is provided by `tcp_reassembler` in [src/tcp.h](../src/tcp.h).
This document explains how it works, and how to use it to reassemble
TCP data features. Like the code it describes, the document a work in 
progress.

When the length of the segment is known, a reassembly request consists
of the initial sequence number of the segment, and the number of bytes
in it, and the first N bytes of the segment.  The format of TLS records
and SSH binary packets contains an explicit indication of the length
of those elements, making it easy to construct a reassembly request.
If, while parsing one of those elements, the length of the element exceeds
the length of the packet, a reassembly request can be created.  Since the
length of the data element is known, the length of the TCP segment is known,
and the reassembler knows exactly what TCP sequence number to look for.

HTTP 1.1 does not contain such an indication, so TCP message
reassembly is used for the method, URI, headers, and other fields.  
A request to reassemble an HTTP1.1 request asks for the remainder of the
TCP message; the reassembler then uses the fact that the TCP Acknowledgement,
or ACK field, of the client's packets will not change while it is sending
the first TCP message.  To be clear, the client increases the ACK field in
the packets that it sends, in order to indicate to the server that it
recieved data.  Since the server waits until it receives the entire 
request before it sends a response, the ACK field does not change while
the client is sending the request, regardless of how many TCP packets it
needs to send to get that message to the server.  

When using the reassembler, it is important to request reassembly of the
entire data element of interest, and to avoid requesting the reassembly
of overlapping segments.  For instance, a TLS Client Hello message contains
an extensions field, and itself is contained in a TLS record.  Reassembly
is applied to the record, because it is the lowest layer, and there is 
no need to also request the reassembly of the extensions field.

Packet loss may prevent the reassembly process from being completed.
To handle these "zombie" cases, the reassembler needs a mechanism to
detect them, and a mechanism to process the incomplete messages.
Detection can be accomplished by maintaining, along with each segment,
a timestamp of when it was created.  A "reaper" function can traverse
this list, process the incomplete segments, and then delete them.

To avoid memory allocation during packet processing, a preallocated
array of segments is used.  To better accomodate different segment
sizes, the reassembler could use a big array of short segments and a
short array of long segments.

