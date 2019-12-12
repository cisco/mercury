/*
 * addr.h
 *
 * interface into address processing functions, including longest
 * prefix matching
 */


#include <string>
#include "mercury.h"

std::string get_asn_info(char* dst_ip);

int addr_init();


