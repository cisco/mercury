#include "lctrie_bgp.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <errno.h>

#include <arpa/inet.h>

int
lct_subnet_set_from_string(lct_subnet_t *subnet, const char *subnet_string) {
  uint32_t addr;
  uint32_t asn;
  uint8_t mask_length;
  unsigned char *dq = (unsigned char *)&addr;

  int num_items_parsed = sscanf(subnet_string,"%hhu.%hhu.%hhu.%hhu/%hhu\t%u",
	 dq + 3, dq + 2, dq + 1, dq, &mask_length, &asn);

  // printf("parsed subnet and ASN string %u.%u.%u.%u/%u\t%u (%u)\n",
  //	 ((addr >> 24) & 0xff), ((addr >> 16) & 0xff), ((addr >> 8) & 0xff), (addr & 0xff), mask_length, asn, num_items_parsed);

  if (num_items_parsed == 6) {

    if ((mask_length == 0) || (mask_length > 32)) {
      fprintf(stderr, "ERROR: %u is not a valid prefix length\n", mask_length);
      return -1;
    }
    
    subnet->addr = addr;
    subnet->len = mask_length;
    subnet->type = IP_SUBNET_BGP;
    subnet->info.bgp.asn = asn;
    return 0;
  }
  return -1;  /* error parsing subnet_string */
}

int
read_prefix_table(char *filename,
                  lct_subnet_t prefix[],
                  size_t prefix_size) {
  int num = 0;
  FILE *infile;
  char *line = NULL;
  size_t line_len = 0;

  // open the file for reading
  if (!(infile = fopen(filename, "r"))) {
    fprintf(stderr, "%s: %s\n", filename, strerror(errno));
    return -1;
  }

  // validate and parse each line of input
  while (-1 != getline(&line, &line_len, infile)) {
    // clip off the trailing newline character
    line[strcspn(line, "\n")] = 0;

    // set the prefix[num] to the subnet and ASN found in line 
    if (lct_subnet_set_from_string(&prefix[num], line) != 0) {
      fprintf(stderr, "error: could not parse subnet string '%s'\n", line);
      return -1;
    }
    
    num++;
  }

  free(line);
  fclose(infile);

  return num;
}

int
read_asn_table(char *filename,
               lct_bgp_asn_t prefix[],
               size_t prefix_size) {
  return -1;
}
