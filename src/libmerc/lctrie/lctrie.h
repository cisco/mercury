#ifndef __LC_TRIE_H__
#define __LC_TRIE_H__
// begin #ifndef guard

#include <stdlib.h>
#include <stdint.h>

#include "lctrie_ip.h"
#include "common.h"

// a large root branch performs best under testing
// and splits up the search space size of the sub-branchs
// signficantly even when there's repeated bases off the 
// root due to shorter prefix matches.
#define ROOT_BRANCH       16

// A branch fill factor of 50%
#define FILLFACT          50


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
//
template <typename T>
struct lct {
  uint32_t ncount;    // number of trie nodes, will always be <= 2 * pcount
  uint32_t bcount;    // number of trie base subnet leaves
  uint8_t shortest;   // shortest base subnet length (just for stats)

  uint32_t *bases;    // array of indexes in the base array to indexes
                      // into the subnet info data array.
  lct_subnet<T> *nets; // pointer to a sorted and prefixed array of subnets
  lct_node_t *root;   // pointer to the root of the trie node tree
};

//using lct_t = lct<uint32_t>;

// internal functions


template <typename T>
static
uint8_t compute_skip(lct<T> *trie, uint32_t prefix, uint32_t first,
                     uint32_t num, uint32_t *newprefix) {
  T low, high;
  uint32_t i;

  // there is no skip factor on the root node
  if ((prefix == 0) && (first == 0)) {
    return 0;
  }

  // Compute the new prefix
  low = REMOVE(prefix, trie->nets[trie->bases[first]].addr);
  high = REMOVE(prefix, trie->nets[trie->bases[first + num - 1]].addr);
  i = prefix;
  while (EXTRACT(i, 1, low) == EXTRACT(i, 1, high)) {
      i++;
  }
  *newprefix = i;

  return (*newprefix - prefix);
}

template <typename T>
static
uint8_t compute_branch(lct<T> *trie, uint32_t prefix, uint32_t first,
                       uint32_t num, uint32_t newprefix) {
  int i, pat, bits, count, patfound;

  // branch factor results in 1 << branch trie subnodes

  // always use a branch factor of 1 for two element arrays
  if (num == 2) {
    return 1;
  }

  // a large root factor may waste entries for the same base off of the root,
  // but performan exceptionally better for longer prefix matches.
  if ((prefix == 0) && (first == 0)) {
    return ROOT_BRANCH;
  }

  // Compute the number of bits that can be used for branching.
  // We have at least two branches. Therefore we start the search
  // at 2^b = 4 branches.
  bits = 1;
  do {
    bits++;
    if (num < ((FILLFACT * (1<<bits)) / 100) ||
        newprefix + bits > sizeof(uint32_t))
      break;
    i = first;
    pat = 0;
    count = 0;
    while (pat < 1<<bits) {
      patfound = 0;
      while (i < first + num &&
             pat == EXTRACT(newprefix, bits, trie->nets[trie->bases[i]].addr)) {
        i++;
        patfound = 1;
      }
      if (patfound)
        count++;
      pat++;
    }
  } while (count >= ((FILLFACT * (1<<bits)) / 100));
  return bits - 1;
}



template <typename T>
static
void build_inner(lct<T> *trie, uint32_t prefix, uint32_t first, uint32_t num, uint32_t pos) {
  int k, p, idx, bits;
  T bitpat;
  uint32_t newprefix = 0, i;
  uint8_t branch;

  constexpr unsigned int bits_in_T = sizeof(T) * 8;

  if (num == 1) {
    trie->root[pos].branch = 0;
    trie->root[pos].skip = 0;
    trie->root[pos].index = first;
  }
  else {
    // calculate the skip and branch for this node
    trie->root[pos].skip = compute_skip(trie, prefix, first, num, &newprefix);
    branch = trie->root[pos].branch = compute_branch(trie, prefix, first, num, newprefix);

    // get a pointer to the next unused trie node which is conveniently
    // located at trie->ncount since our caller allocated this node
    // for us.  save off the child pointer for this node to it.
    idx = trie->ncount;
    trie->root[pos].index = idx;

    // ok, we need to allocate our child nodes before we recurse over them
    trie->ncount += 1 << branch;

    // Build the subtrees
    p = first;
    for (bitpat = 0; bitpat < (1 << branch); ++bitpat) {
      k = 0;
      while (p + k < first + num &&
             EXTRACT(newprefix, branch, trie->nets[trie->bases[p + k]].addr) == bitpat) {
        ++k;
      }

      if (k == 0) {
        // The leaf should have a pointer either to p-1 or p,
        // whichever has the longest matching prefix
        int match1 = 0, match2 = 0;

        // Compute the longest prefix match for p - 1
        if (p > first) {
          int prep, len;
          prep =  trie->nets[trie->bases[p - 1]].prefix;
          while (prep != IP_PREFIX_NIL && match1 == 0) {
            len = trie->nets[prep].len;
            if (len > newprefix &&
                EXTRACT(newprefix, len - newprefix, trie->nets[trie->bases[p - 1]].addr) ==
                EXTRACT(bits_in_T - branch, len - newprefix, bitpat))
              match1 = len;
            else
              prep = trie->nets[prep].prefix;
          }
        }

        // Compute the longest prefix match for p
        if (p < first + num) {
          int prep, len;
          prep =  trie->nets[trie->bases[p]].prefix;
          while (prep != IP_PREFIX_NIL && match2 == 0) {
            len = trie->nets[prep].len;
            if (len > newprefix &&
                EXTRACT(newprefix, len - newprefix, trie->nets[trie->bases[p]].addr) ==
                EXTRACT(bits_in_T - branch, len - newprefix, bitpat))
              match2 = len;
            else
              prep = trie->nets[prep].prefix;
          }
        }

        if ((match1 > match2 && p > first) || p == first + num)
          build_inner(trie, newprefix + branch, p - 1, 1, idx + bitpat);
        else
          build_inner(trie, newprefix + branch, p, 1, idx + bitpat);
      } else if (k == 1 && trie->nets[trie->bases[p]].len - newprefix < branch) {
        bits = branch - trie->nets[trie->bases[p]].len + newprefix;
        for (i = bitpat; i < bitpat + (1 << bits); i++)
          build_inner(trie, newprefix + branch, p, 1, idx + i);
        bitpat += (1 << bits) - 1;
      } else
        build_inner(trie, newprefix + branch, p, k, idx + bitpat);
      p += k;
    }
  }
}


// lifecycle functions
//
// we store pointers to the subnet passed in here, so the subnet array must
// remain static during the lifetime of the trie.  if the array must be changed,
// free the trie before doing so and recreate it afterwards.  This doesn't bode
// well for a large number of dynamic updates, but keeping updates to a minimum
// and potentially double buffering the data can reduce latency for these
// events.

// since the build algorithm is recursive, we'll pass this API entry point
// into an interior build function
template <typename T>
int lct_build(lct<T> *trie, lct_subnet<T> *subnets, uint32_t size) {
  // why are you hitting yourself, mcfly?
  if (!trie || !subnets || !size)
    return -1;

  // user is responsible for the outer struct,
  // and we're responsible for the interior memory
  trie->nets = subnets;

  // bases will never be more than size, but we will need to
  // shrink it back down after it's allocated
  trie->bases = (uint32_t *) malloc(size * sizeof(uint32_t));

  // allocate and count the bases
  trie->bcount = 0;
  if (!trie) {
    fprintf(stderr, "ERROR: failed to allocate trie bases index buffer\n");
    return -1;
  }

  constexpr unsigned int bits_in_T = sizeof(T) * 8;
  trie->shortest = bits_in_T;  // max subnet prefix length (single address)
  for (int i = 0; i < size; ++i) {
    if (IP_BASE == subnets[i].type) {
      // save off the base's index in the subnet array
      // and increment the bases counter
      trie->bases[trie->bcount++] = i;
      if (subnets[i].len < trie->shortest)
        trie->shortest = subnets[i].len;
    }
  }

  // reallocate the base index buffer back down to the actual size.
  trie->bases = (uint32_t *) realloc(trie->bases, trie->bcount * sizeof(uint32_t));

  // give a 2MB buffer, and we'll shrink it down once we've built the trie
  trie->root = (lct_node_t *) malloc((size + 2000000) * sizeof(lct_node_t));
  if (!trie->root) {
    free(trie->bases);
    fprintf(stderr, "ERROR: failed to allocate trie node buffer\n");
    return -1;
  }

  // hande off to the inner recursive function
  trie->ncount = 1; // we start with the root node allocated
  build_inner(trie, 0, 0, trie->bcount, 0);

  // shrink down the trie node array to its actual size
  lct_node_t *tmp = (lct_node_t *) realloc(trie->root, trie->ncount * sizeof(lct_node_t));
  if (tmp == NULL) {
      free(trie->root);
      return -1;   /* error: reallocation failed */
  }
  trie->root = tmp;

  return 0;
}

template <typename T>
void lct_free(lct<T> *trie) {
  if (!trie)
    return;

  // don't free the external subnet array.
  // that's under outside control.
  free(trie->bases);
  trie->bases = NULL;
  trie->root = NULL;
  trie->ncount = 0;
  trie->bcount = 0;
}

//extern void lct_free(lct_t *trie);

// trie search function
// return the IP subnet corresponding to the element,
// otherwise return NULL if not found
// key must be provided in host byte ordering
//
template <typename T>
lct_subnet<T> *lct_find(lct<T> *trie, T key) {
  lct_node_t *node;
  int pos, branch, idx;
  uint32_t prep;
  T bitmask;

  // idiot check
  if (!trie)
    return NULL;

  // Traverse the trie
  node = &trie->root[0];
  pos = node->skip;
  branch = node->branch;
  idx = node->index;
  while (branch != 0) {
    node = &trie->root[idx + EXTRACT(pos, branch, key)];
    pos += branch + node->skip;
    branch = node->branch;
    idx = node->index;
  }

  /* Was this a hit? */
  bitmask = trie->nets[trie->bases[idx]].addr ^ key;
  if (EXTRACT(0, trie->nets[trie->bases[idx]].len, bitmask) == 0)
    return &trie->nets[trie->bases[idx]];

  /* If not, look in the prefix tree */
  prep = trie->nets[trie->bases[idx]].prefix;
  while (prep != IP_PREFIX_NIL) {
    if (EXTRACT(0, trie->nets[prep].len, bitmask) == 0)
      return &trie->nets[prep];
    prep = trie->nets[prep].prefix;
  }

  return NULL;
}

// end #ifndef guard
#endif
