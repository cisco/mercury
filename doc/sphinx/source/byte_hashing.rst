.. Mercury documentation subfile

Byte-String Hashing
===================

``universal61::byte_hasher`` provides a keyed universal hash for arbitrary
byte strings.  It is intended for internal hash tables, including tables that
store fingerprints and event records, rather than for authentication or
general-purpose cryptography.

The implementation uses the Mersenne-prime field
``p = 2^61 - 1``.  It encodes the input length followed by little-endian
seven-byte field elements and evaluates the resulting sequence with Horner's
method.  More precisely, if ``L`` is the byte-string length, the encoded
sequence starts with ``L mod p``, followed by ``floor(L / p)`` when ``L >= p``,
and then contains seven-byte little-endian blocks, with zero-extension only in
the final partial block.  If that sequence is ``e[0], ..., e[n-1]``, the
returned hash is:

::

   H(e) = b * a^(n+1) + sum(i = 0 .. n-1, e[i] * a^(n-i)) mod p

where ``a`` is the nonzero secret multiplier and ``b`` is the secret offset.
For a block containing bytes ``b[0], ..., b[r-1]``,
``e[i] = sum(j = 0 .. r-1, b[j] * 2^(8*j))``.  Therefore each byte has the
secret-dependent coefficient ``2^(8*j) * a^(n-i)`` in the expanded polynomial.
The final multiplication is deferred until ``finish()``, so each byte is
keyed without adding work to the append and batching paths.  The multiplier
and offset are generated once when the hasher is constructed; hashing itself
performs no random-device access or allocation.

For standalone byte strings with length below ``p``, the encoding is
injective: it includes the byte length and uses a fixed seven-byte
representation, including zero-padding only in the final partial block.  The
same guarantee applies to compound encodings only when every component field
has length below ``p``; otherwise, the conditional quotient limb is not
self-delimiting.  Consequently, for two distinct equal-length encodings with
``d`` elements, the offset cancels and the difference polynomial has degree at
most ``d - 1``.  For different encoded lengths, a conservative bound is
degree ``d``, where ``d`` is the larger length.  A nonzero polynomial of degree
``r`` over a field has at most ``r`` roots, so a uniformly selected nonzero
multiplier collides with probability at most ``r / (p - 1)``.  The final
multiplication adds only the root ``a = 0``, which is excluded from the key
space, and therefore preserves the bound.  The offset randomizes individual
outputs but does not change the collision bound.

The eight-element batching in the implementation is an algebraic
optimization.  It evaluates eight Horner steps as one polynomial expression
and performs one field reduction instead of eight, producing the same result
as the unbatched recurrence.

The construction is based on polynomial universal hashing and is intended to
make offline collision-set construction difficult when the process-local key
is not exposed.  It is not a cryptographic hash and should not be used when
hash outputs are exposed as an oracle to an attacker.

The design is informed by the following literature:

* J. L. Carter and M. N. Wegman, `Universal Classes of Hash Functions
  <https://doi.org/10.1016/0022-0000(79)90044-8>`_, Journal of Computer and
  System Sciences 18(2), 1979.
* O. Kaser and D. Lemire, `Strongly Universal String Hashing is Fast
  <https://doi.org/10.1093/comjnl/bxt070>`_, The Computer Journal 57(11),
  2014.
* S. A. Crosby and D. S. Wallach, `Denial of Service via Algorithmic
  Complexity Attacks
  <https://static.usenix.org/event/sec03/tech/full_papers/crosby/crosby_html/>`_,
  USENIX Security 2003.
* N. Bar-Yosef and A. Wool, `Remote Algorithmic Complexity Attacks against
  Randomized Hash Tables <https://doi.org/10.5220/0002118101170124>`_,
  SECRYPT 2007.

.. doxygenfile:: universal61_bytes.hpp
   :project: mercury

.. doxygennamespace:: universal61
   :project: mercury
   :members:

.. doxygenstruct:: universal61::byte_hash_secret
   :project: mercury
   :members:

.. doxygenclass:: universal61::byte_hash_state
   :project: mercury
   :members:

.. doxygenclass:: universal61::byte_hasher
   :project: mercury
   :members:
