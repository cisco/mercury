# Guidelines for implementing data parsers

## Data Representation

A single byte is represented as a `uint8_t`.  A contiguous sequence of
readable bytes is represented as a pair of pointers: `data` points to
the first byte in the sequence and `data_end` points to the byte
immediately past its end.  (This is the usual half-open range used in
C++.)

A datum is in one of the states `null`, `readable`, or `empty`, which
is determined by the values of its members `datum::data` and
`datum::data_end` as follows:

       State   |    data           |   data_end
   -------------|---------------------|-------------------------------
       null     |    `nullptr`       |   `nullptr`
       readable |    `data>nullptr`  |   `data_end > data`
       empty    |    `data>nullptr`  |   `data_end == data`


A readable datum corresponds to a non-empty byte sequence, and a null
datum indicates the absence of a sequence, or an error condition.  An
empty datum corresponds to an empty sequence, which is not an error
condition.  Whenever data != nullptr, data_end is initialized as a
proper non-negative offset to data, so that the pointers refer to the
same region of memory.

A readable datum can represent an input sequence of bytes being
parsed, or a sequence of bytes corresponding to a lexical element.  A
null datum can represent the result of a failed parsing attempt.


## Parsers

Data parsers are implemented as classes (or class templates) that have
a constructor that takes a `datum &input` as a parameter.  The
constructor is responsible for determining whether or not the input is
in the correct format, and initializing all of its data members.  We
use the following conventions this type of constructor:

   * it must not assume that `input` is readable, and it must detect
     and ignore a null datum, without causing a fault,
   * it must not access any bytes that are outside of the range
     `[data,data_end)`,
   * if it is not possible to construct an object from the byte
     sequence in the datum (for instance, if there are not enough
     bytes), then the input datum is set to the null state,
   * otherwise, the `data` pointer must be advanced to reflect the
     extent of the bytes consumed by decoding/parsing an object during
     construction.

These conventions ensure that a data parser constructor can use a
member initializer list, passing the input datum to each successive
member.  This facilitates composability: objects made by composing
together objects that follow these conventions will also follow these
conventions.




