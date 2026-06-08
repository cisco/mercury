///
/// \file doctest_main.cc
///
/// Provides main() entry point for all unit tests.
///
/// This file is compiled and linked with other test files to provide a single
/// main() function. The DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN macro tells doctest
/// to generate main(), which discovers and runs all TEST_CASE, TEST_CASE_FIXTURE,
/// and SCENARIO tests defined in the linked test files.
///
/// See mk/test_libmerc.mk for which test files are linked with this main().
///
/// Copyright (c) 2025 Cisco Systems, Inc. All rights reserved.
/// License at https://github.com/cisco/mercury/blob/master/LICENSE
///

#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "doctest.h"
