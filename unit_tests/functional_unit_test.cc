/*
 * functional_unit_test.cc
 *
 * 
 * Copyright (c) 2021 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include "libmerc_driver_helper.hpp"
#include "bencode.h"
#include "snmp.h"
#include "tofsee.hpp"
#include "ip_address.hpp"
#include "utf8.hpp"
#include "tsc_clock.hpp"
#include "json_string.hpp"
#include "ftp.hpp"
/*
 * The unit_test() functions defined in header files
 * can be tested here using CHECK framework.
 * The below tests will be run as part of
 * make test and verified.
 */
TEST_CASE("Testing unit_test() defined in class") {
    CHECK(bencoding::dictionary::unit_test() == true);
    CHECK(snmp::unit_test() == true);
    CHECK(tofsee_initial_message::unit_test() == true);
    CHECK(tls_extensions::unit_test() == true);
    CHECK(ipv6_address_string::unit_test() == true);
    CHECK(utf8_string::unit_test() == true);
    CHECK(utf8_safe_string_unit_test() == true);
    CHECK(tsc_clock::unit_test() == true);
    CHECK(json_string::unit_test() == true);
    CHECK(ftp::unit_test()==true);
}
