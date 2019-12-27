#ifndef __LC_TRIE_H__
#define __LC_TRIE_H__
// begin #ifndef guard

#include <stdlib.h>
#include <stdint.h>

#include "lctrie_ip.h"

/* remove the first p bits from string */
#define REMOVE(p, str)   ((str)<<(p)>>(p))

// Since a Trie is a radix tree, the number of
// operations to lookup a key in a tree is dependent
// on the depth of the tree.  The more bits allow for
// a greater number of child nodes per node and more
// bit comparisons in a single traversal of the trie,
// or a trie-versal. (lame programmer joke)
//
// Level compressed (LC) Trie
// a multibit trie implementation with a densely
// packed root node for less densely packed child
// sub-tries for minimal tree depth.
//
// This LC Trie is an array indexed implementation
// that attempts to make use of byte aligned values
// to reduce the amount of bit shifting operations
// in the cpu for using the data structures.
//
// Other reference implementations make use of bit packing
// to conserve memory at the expense of CPU operations.
// We will attempt to only make use of bit operations when
// actually manipulating the key data itself.
//
// A trie branch node has n children which are indexed by
// the search key's n-bit values after skipping m-bits from
// the current search position where n is the node's branch value
// and m is the node's skip value.
//
// Since all of the details about the subnets are in the external
// subnet structure, we only need to store the index to the
// the node in that array to get information about the subnet
// size and prefix address.  We also have the prefix pointer to
// walk up the tree to compare against prefixes of this base node
// in the tree.
typedef struct lct_node {
  uint8_t branch;         // size of the child node array
  uint8_t skip;           // number of bits to skip of the key before extracting
  uint32_t index;         // index of this node's first child if a branch
} lct_node_t;
// Leave this structure unpacked so the compiler will memory align it
// in a mannder that favors fast access over memory unit size.

// The size of the the trie is going to be
// 2 * number of bases stored with nulls
// sparsely mixed amongst the trie levels.

// LC Trie data structure
// size - number of nodes in the trie
// trie - the root of the trie
typedef struct lct {
  uint32_t ncount;    // number of trie nodes, will always be <= 2 * pcount
  uint32_t bcount;    // number of trie base subnet leaves
  uint8_t shortest;   // shortest base subnet length (just for stats)

  uint32_t *bases;    // array of indexes in the base array to indexes
                      // into the subnet info data array.
  lct_subnet_t *nets; // pointer to a sorted and prefixed array of subnets
  lct_node_t *root;   // pointer to the root of the trie node tree
} lct_t;

// lifecycle functions
//
// we store pointers to the subnet passed in here, so the subnet array must
// remain static during the lifetime of the trie.  if the array must be changed,
// free the trie before doing so and recreate it afterwards.  This doesn't bode
// well for a large number of dynamic updates, but keeping updates to a minimum
// and potentially double buffering the data can reduce latency for these
// events.
extern int lct_build(lct_t *trie, lct_subnet_t *subnets, uint32_t size);
extern void lct_free(lct_t *trie);

// trie search function
// return the IP subnet corresponding to the element,
// otherwise return NULL if not found
// key must be provided in host byte ordering
extern lct_subnet_t *lct_find(lct_t *trie, uint32_t key);

// end #ifndef guard
#endif
