# Requirements for C++ Protocol Implementations

Mercury protocol implementations must follow these guidelines.

## General

- C++17 must be used, and must work with g++ and clang++.

- Source files must be named *.cpp and *.hpp.

- Each source file must contain a license reference in a comment at
  the top.

- Indentation must use four spaces.

- Curly braces must be used with if/else statements.

- C++ style comments should be used, except for files that aim for C
  compatibility.

- Each source file must be documented using doxygen/sphinx comments,
  e.g. \brief, \param, etc.  There should be an empty comment line
  above the struct, class, or function to which the comment refers.

- Deprecated functions must not be used.

- Protocol handlers should not allocate or deallocate memory during
  packet processing.  This applies to memory management functions like
  new, delete, malloc, free, realloc, as well as C++ standard library
  functions that indirectly allocate or free memory, such as
  std::string operations, std::vector::push_back(), etc.

- Each protocol implementation should be contained within a namespace.


## Data Parsing/Decoding

- class datum (src/libmerc/datum.h) is used to represent a contiguous
  sequence of bytes from which data can be read.  A datum object is in
  one of the states null, readable, or empty.

- Data parsers must not directly access pointers; instead, they should
  use a safe alternative:

   - a member functions of class datum,

   - the template class encoded<T>, to decode an integer type T,

   - the template class literal<>, to accept a literal string of
     bytes (and reject any non-matching input data),

   - the template class skip_bytes<N>, to ignore the next N bytes,

   - the template class lookahead<T>, to check whether the input
     can be parsed as an object of type T,

   - the template class sequence<T>, to parse a sequence of objects of
     type T from the input,

   - the classes one_or_more, ignore_char_class, exactly_n,
     up_to_required_byte, alpha_numeric, digits, or hex_digits, for
     parsing sequences from a character class,

   - the classes one_or_more_up_to_delimeter or escaped_string_up_to,
     to parse arbitrary data up to a (possibly escaped) delimeter
     character,

   - class tlv, for ASN.1 data.

Examples are provided in ../src/examples.cpp.


## Selective, Lazy, Non-owning Parsing

Mercury uses a selective, lazy, non-owning data parsing strategy:

- instead of making a copy of a sequence of bytes, the parser should
  set a datum to refer to the sequence of bytes in the packet, and

- a parser should avoid parsing data until it is necessary, and
  instead determine the high level structure of a message, storing
  just enough data to understand that structure, allowing the the user
  of the library to determine exactly what data elements will be fully
  parsed, and providing functions to do so.


## Composable Safe Parser Classes

- Data parsers must be implemented as classes (or class templates)
  that have a constructor that takes a `datum &input` as a parameter.
  This constructor is responsible for determining whether or not the
  input is in the correct format, and initializing all of its data
  members.  The following conventions must be used for this type of
  constructor:

   * it must not assume that `input` is readable, and it must detect
     and ignore a null datum, without causing a fault,

   * it must not access any bytes that are outside of the range
     `[data,data_end)`,

   * if it is not possible to construct an object from the byte
     sequence in the datum (for instance, if there are not enough
     bytes), then `input` is set to the null state,

   * otherwise, the `data` pointer must be advanced to reflect the
     extent of the bytes consumed by decoding/parsing an object during
     construction, and

   * the constructor must initialize all data members using a member
     initializer list, except for those that use a default
     constructor.

   * If necessary, the member initalizer can invoke a static member
     function that accepts a `datum &` and returns an object of the
     appropriate class, in which case the function should enable
     Return Value Optimization (RVO) to avoid an unneeded copy.

These conventions facilitate composability by ensuring that conforming
classes can be used as data members of other conforming classes.

Composable safe parser classes should not have a default constructor.
They may have a constructor that accepts a `datum &&` rvalue
reference, to make it easy to construct and pass a temporary `datum`
to a class.  A constructor that takes a datum rvalue reference should
merely invoke the `datum &` constructor.


## JSON Output

- JSON output must use the json_object and json_array classes from
  src/libmerc/json_object.h.

- All JSON keys must be `const char *` strings.  Do not use packet
  data as a JSON key.

- All JSON values that are strings must be valid UTF-8 with JSON
  characters escaped.  Use class utf8_safe_string where needed.

- All JSON keys and value-strings must not contain spaces or
  dashes, and should be lowercase.

- There should be no empty JSON objects or empty JSON arrays.

- For compressibility, highly variable fields (e.g. IP.ID) should be
  at the tail end of a record, not the front.

- In an array of objects, the objects can have distinct schema, as
  long as any name that appears in more than one object schema has the
  same type in all objects.

- Prefer flat schemas where possible; avoid arrays of objects unless
  necessary.


## Enumerations

When a protocol uses a set of assigned numbers that have meaning
within the protocol, such as the [TLS Ciphersuites]
(https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-4),
the implementation should define an enum class to represent those
values.

- The enum class must be used in the code, instead of an integer literal.

- The implementation should define a function that maps an enum to the
  descriptive string, such as "tls_null_with_null_null".  These
  strings should prefer lowercase with underscores instead of spaces.

- The enum and the corresponding descriptive strings should be derived
  from the Internet Assigned Numers Authority, the IEEE, or other
  sources as needed.


