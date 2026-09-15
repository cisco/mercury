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
method.  The multiplier and offset are generated once when the hasher is
constructed; hashing itself performs no random-device access or allocation.

For two distinct encodings, the difference of the corresponding hash
polynomials is nonzero.  If the larger encoding contains ``d`` field elements,
there are at most ``d - 1`` possible nonzero multipliers that produce a
collision, giving a bound of ``(d - 1) / (p - 1)`` for a uniformly selected
multiplier from the nonzero field elements.  The offset randomizes individual
outputs but does not change that collision bound.

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
