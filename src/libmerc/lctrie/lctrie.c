#include "lctrie.h"

#include <stdio.h>

// a large root branch performs best under testing
// and splits up the search space size of the sub-branchs
// signficantly even when there's repeated bases off the 
// root due to shorter prefix matches.
#define ROOT_BRANCH       16

// A branch fill factor of 50%
#define FILLFACT          50

static
uint8_t compute_skip(lct_t *trie, uint32_t prefix, uint32_t first,
                         uint32_t num, uint32_t *newprefix) {
  uint32_t low, high;
  uint32_t i;

  // there is no skip factor on the root node
  if ((prefix == 0) && (first == 0)) {
    return 0;
  }

  // Compute the new prefix
  low = REMOVE(prefix, trie->nets[trie->bases[first]].addr);
  high = REMOVE(prefix, trie->nets[trie->bases[first + num - 1]].addr);
  i = prefix;
  while (EXTRACT(i, 1, low) == EXTRACT(i, 1, high))
    i++;
  *newprefix = i;

  return (*newprefix - prefix);
}

static
uint8_t compute_branch(lct_t *trie, uint32_t prefix, uint32_t first,
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

static
void build_inner(lct_t *trie, uint32_t prefix, uint32_t first, uint32_t num, uint32_t pos) {
  int k, p, idx, bits;
  uint32_t bitpat, newprefix = 0, i;
  uint8_t branch;

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
                EXTRACT(32 - branch, len - newprefix, bitpat))
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
                EXTRACT(32 - branch, len - newprefix, bitpat))
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

// since the build algorithm is recursive, we'll pass this API entry point
// into an interior build function
int lct_build(lct_t *trie, lct_subnet_t *subnets, uint32_t size) {
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

  trie->shortest = 32;  // max subnet prefix length (single address)
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

void lct_free(lct_t *trie) {
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

lct_subnet_t *lct_find(lct_t *trie, uint32_t key) {
  lct_node_t *node;
  int pos, branch, idx;
  uint32_t bitmask, prep;

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
