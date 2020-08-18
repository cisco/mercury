## Safe Selective Parsing of Truncated Certificates and Other Network Data
### David McGrew, August 18, 2020


One of the biggest challenges in network data collection and analysis
is that of parsing network data with safety, performance, and
flexibility.  Network data formats are complex, and packet data is
often truncated, and too often misformatted.  In mercury and
cert-analyze, bounds checking is enforced through structured
programming, with data structures and functions that provide
efficiency and flexibility.  This note explains that approach in more
detail (and it is a work in progress).

Network packets occupy contiguous regions of memory.  A substring of a
packet can be identified by a pair of pointers indicating its start
and its end.  Thus our fundamental data type is

```c++
   struct datum {
      uint8_t *start;
      uint8_t *end;
   };
```

Roughly speaking, our strategy is to use a `struct datum` in every place
where a naked pointer would otherwise be used, so that the extent of
the data is always known, and to provide access to data strings only
through functions that provide appropriate checking.

A datum is in one of the states `null`, `readable`, or `empty`

   start      |   end                     |    State
   -----------|---------------------------|-----------------
   NULL       |   NULL                    |    null
   non-NULL   |   non-NULL, end > start   |    readable
   non-NULL   |   non-NULL, end == start  |    empty

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
parses that data and advances the start pointer, and assigns the start
and end pointers for the method, uri, protocol, and headers.  A `struct http_request`
object must have a scope that does not exceed that of the `data_buffer`.

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
represent the start and end of the header along with its internal
partitions, but we can avoid a modest amount of pointer arithmetic
that would otherwise be needed for bounds checkig.

