## Safe Selective Parsing of Truncated Certificates and Other Network Data
#### David McGrew, September 4, 2020


One of the important challenges in network data collection and
analysis is that of parsing packets with safety, performance, and
flexibility.  Network data formats are complex, and packet data is
often truncated, and is too often misformatted.  Poorly designed
network parsers have been the source of many severe software bugs.  To
achieve performance and efficiency, Mercury (and cert-analyze) use
*in-situ, selective parsing*, with bounds checking enforced through
structured programming.  This note explains that approach in more
detail (and is a work in progress).

Abstractly, a packet parser reads a byte stream, determines what
protocol and messages it contains, and converts the protocol's data
elements into integers, strings, and other objects that are
programmatically accessible.  **Selective parsing** converts only
selected data elements, skipping over uninteresting ones for the sake
of efficiency.  **In-situ parsing** avoids memory allocation by creating
references to data elements in the packet buffer.

Network packets occupy contiguous regions of memory.  A substring of a
packet can be identified by a pair of pointers indicating its start
and its end.  Thus our fundamental data type is

```c++
   struct datum {
      uint8_t *data;
      uint8_t *data_end;
   };
```

as defined in [src/datum.h](../src/datum.h).  Roughly speaking, our
strategy is to use a `struct datum` in every place where a naked
pointer would otherwise be used, so that the extent of the data is
always known, and to provide access to data strings only through
functions that provide appropriate checking.

A datum is in one of the states `null`, `readable`, or `empty`

   data       |   data_end                    |    State
   -----------|-------------------------------|-----------------
   NULL       |   NULL                        |    null
   non-NULL   |   non-NULL, data_end > data   |    readable
   non-NULL   |   non-NULL, data_end == data  |    empty

A readable datum is not necessarily complete, in the sense that it
might contain data that has been truncated, such as the first ten
bytes of a 20-byte TCP header.

We chose to use a pointer-pair instead of the commonplace convention
of representing a byte string as a pointer and a length (size_t).  It
is simpler to compare two pointers, as opposed to performing pointer
arithmetic before bounds checking.  Using a pair of pointers also has
the advantage that, when incrementing the data pointer, there is no
need to decrement the corresponding length.

Even if a struct datum is readable, there is no guarantee that the
region of memory it references is complete, so we provide functions
for parsing and operating on the referenced data that have
bounds checking when needed.  For instance, an ASCII string may not be
null-terminated, so several of the C library string functions like
strlen() cannot be used, but strnlen() can.  We provide small wrapper
functions around strnlen() and similar functions, to expose a safe
interface to the data.

More formally, parsing a byte string means assigning one or more
struct datum elements to it.  A **top-level** parsing is one that
assigns an entire byte string to one or more elements.  For instance,
an http_request is represented as

```c++
    struct http_request {
        struct datum method;
        struct datum uri;
        struct datum protocol;
        struct datum headers;

        http_request() : method{NULL, NULL}, uri{NULL, NULL}, protocol{NULL, NULL}, headers{NULL,NULL} {}

        void parse(struct datum &data_buffer);

    };
```

The member function `parse()` takes a (reference to) a datum as input,
parses that data and advances the data pointer, and assigns the `data`
and `data_end` pointers for the method, uri, protocol, and headers.  A
`struct http_request` object must have a scope that does not exceed
that of the `data_buffer`.

An HTTP request contains a variable number of headers; in the example
above, 'struct headers' represents all of them.  Accessing an
individual header field, such as "User-Agent", requires parsing that
struct.  This **lower-level** parsing can be performed after the
top-level parsing completes, with the help of some specialized member
functions.  The strategy of separating the top-level parsing and
lower-level parsing avoids dynamic memory allocation, which would be
necessary if a std::vector of header fields had been used, since it is
impossible to predict in advance how many headers will be present.
Formally, an http_request object represents the top of the parse tree,
and lower-level terminals (such as HTTP header fields) are accessed
through functions that parse a top-level data element.

The overhead for this approach is low; it trades some storage for
computation.  In the http_request example, there are eight pointers
instead of the minimum number of five pointers that are needed to
represent the data and data_end of the header along with its internal
partitions, but we can avoid a modest amount of pointer arithmetic
that would otherwise be needed for bounds checking.

The function `http_request::parse(struct datum &data_buffer)` takes a
datum as input, reads that data, and assigns the `method`, `uri`,
`protocol`, and `headers` data elements.  Those elements are
initialized to `NULL` values when the http_request is constructed.  If
the parsing is completely successful, then all of the elements will
point to the appropriate regions of memory.  But what happens if the
data_buffer contains a truncated HTTP request?  If the parsing of the
`protocol` element fails, for instance, then that element will be left
in the `NULL` state.  Additionally, the data_buffer will be set in the
`empty` state, so that the attempt to parse the `headers` element can
detect the fact that the data_buffer can no longer be parsed.
Importantly, all of the parsing routines check to see if the datum
they are reading from is in a `readable` state.  This provides safety,
and allows for a very readable coding style in which data elements are
successively parsed from a data buffer.  If that data buffer is not
readable, there is a slight performance penalty for performing several
`readable` checks, but this penalty may be acceptable, especially if
the data buffer is typically readable.  If performance is a concern,
then the parsing routine can check for readabiltiy and return early if
need be, leaving the data elements corresponding to unparsed data in
their `NULL` state.




