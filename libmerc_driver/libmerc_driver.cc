/*
 * libmerc_driver.cc
 *
 * main() file for libmerc.so test driver program
 *
 * Copyright (c) 2020 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>
#include <string>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <array>
#include <stdexcept>

#include "../src/libmerc/libmerc.h"
#include "../src/libmerc/pkt_proc.h"
#include "catch2/catch.hpp"

namespace snort {
#define SO_PUBLIC

    SO_PUBLIC void LogMessage(const char*, ...) __attribute__((format (printf, 1, 2)));
    SO_PUBLIC void LogMessage(FILE*, const char*, ...) __attribute__((format (printf, 2, 3)));
    SO_PUBLIC void WarningMessage(const char*, ...) __attribute__((format (printf, 1, 2)));
    SO_PUBLIC void ErrorMessage(const char*, ...) __attribute__((format (printf, 1, 2)));

    [[noreturn]] SO_PUBLIC void FatalError(const char*, ...) __attribute__((format (printf, 1, 2)));
}

unsigned char client_hello_eth[] = {
  0x00, 0x50, 0x56, 0xe0, 0xb0, 0xbc, 0x00, 0x0c, 0x29, 0x74, 0x82, 0x2f,
  0x08, 0x00, 0x45, 0x00, 0x01, 0x61, 0xd5, 0xeb, 0x40, 0x00, 0x40, 0x06,
  0x58, 0x0c, 0xc0, 0xa8, 0x71, 0xed, 0x97, 0x65, 0x41, 0xa4, 0x80, 0x2a,
  0x01, 0xbb, 0xdd, 0x07, 0xfe, 0x40, 0x25, 0x00, 0x2e, 0x63, 0x50, 0x18,
  0xfa, 0xf0, 0x0c, 0xf3, 0x00, 0x00, 0x16, 0x03, 0x01, 0x01, 0x34, 0x01,
  0x00, 0x01, 0x30, 0x03, 0x03, 0x5b, 0x1f, 0x43, 0x3b, 0x2f, 0x09, 0x1c,
  0x61, 0xff, 0xd5, 0x1d, 0x3d, 0x8f, 0x00, 0x8f, 0xea, 0x86, 0x3f, 0xb6,
  0xc3, 0x72, 0x6e, 0x7f, 0x05, 0x6b, 0x01, 0x9e, 0xc7, 0x68, 0xcd, 0x12,
  0x58, 0x20, 0xf0, 0xa3, 0x04, 0x3a, 0x4f, 0x60, 0x89, 0x7b, 0x16, 0x89,
  0xf7, 0x46, 0xcf, 0x3c, 0x69, 0x03, 0xf9, 0xf6, 0x06, 0xa7, 0x7f, 0x53,
  0x36, 0xd4, 0xe2, 0x16, 0x33, 0xe9, 0x88, 0x48, 0xff, 0x14, 0x00, 0x3e,
  0x13, 0x02, 0x13, 0x03, 0x13, 0x01, 0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f,
  0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f, 0x00, 0x9e,
  0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67,
  0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33,
  0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f,
  0x00, 0xff, 0x01, 0x00, 0x00, 0xa9, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e,
  0x00, 0x00, 0x0b, 0x6e, 0x79, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x2e, 0x63,
  0x6f, 0x6d, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0a,
  0x00, 0x0c, 0x00, 0x0a, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00, 0x19,
  0x00, 0x18, 0x00, 0x23, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17,
  0x00, 0x00, 0x00, 0x0d, 0x00, 0x30, 0x00, 0x2e, 0x04, 0x03, 0x05, 0x03,
  0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b,
  0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01,
  0x03, 0x03, 0x02, 0x03, 0x03, 0x01, 0x02, 0x01, 0x03, 0x02, 0x02, 0x02,
  0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x00, 0x2b, 0x00, 0x09, 0x08, 0x03,
  0x04, 0x03, 0x03, 0x03, 0x02, 0x03, 0x01, 0x00, 0x2d, 0x00, 0x02, 0x01,
  0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x7f,
  0x36, 0x7d, 0x60, 0x25, 0x06, 0x55, 0xca, 0xbb, 0x18, 0xd3, 0x4c, 0x84,
  0xcc, 0x5b, 0x14, 0xcd, 0x0a, 0x95, 0xe9, 0x06, 0x13, 0x5d, 0xd7, 0x6a,
  0xee, 0x62, 0x2b, 0x2b, 0x54, 0x1c, 0x17
};
size_t client_hello_eth_len = sizeof(client_hello_eth);

unsigned char tcp_syn[] = {
  0x00, 0x50, 0x56, 0x8e, 0x1d, 0xdc, 0x00, 0x50, 0x56, 0xa2, 0x71, 0xbf,
  0x08, 0x00, 0x45, 0x00, 0x00, 0x34, 0x58, 0x5b, 0x40, 0x00, 0x80, 0x06,
  0x41, 0x99, 0x0a, 0x0a, 0x01, 0x70, 0x0d, 0xf9, 0x47, 0x5d, 0xd2, 0x7e,
  0x01, 0xbb, 0x68, 0x4d, 0xc1, 0x2d, 0x00, 0x00, 0x00, 0x00, 0x80, 0x02,
  0xfa, 0xf0, 0x15, 0x9b, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x01, 0x03,
  0x03, 0x08, 0x01, 0x01, 0x04, 0x02
};

unsigned char firefox_client_hello_eth[] = {
  0x00, 0x50, 0x56, 0x8e, 0x1d, 0xdc, 0x00, 0x50, 0x56, 0xa2, 0x71, 0xbf,
  0x08, 0x00, 0x45, 0x00, 0x02, 0x2d, 0x58, 0x5d, 0x40, 0x00, 0x80, 0x06,
  0x3f, 0x9e, 0x0a, 0x0a, 0x01, 0x70, 0x0d, 0xf9, 0x47, 0x5d, 0xd2, 0x7e,
  0x01, 0xbb, 0x68, 0x4d, 0xc1, 0x2e, 0xb1, 0x1b, 0xb4, 0x8d, 0x50, 0x18,
  0x04, 0x00, 0xd6, 0x50, 0x00, 0x00, 0x16, 0x03, 0x01, 0x02, 0x00, 0x01,
  0x00, 0x01, 0xfc, 0x03, 0x03, 0x3e, 0xe1, 0x7f, 0xbd, 0x7c, 0xbc, 0x30,
  0xdb, 0xa4, 0xf4, 0x74, 0xbe, 0x4a, 0x08, 0xa4, 0x8b, 0xf1, 0x5a, 0x82,
  0x78, 0x8a, 0x91, 0xf7, 0x00, 0xec, 0x25, 0xed, 0x6e, 0x5f, 0xea, 0xfb,
  0x3c, 0x20, 0x98, 0x79, 0xf8, 0xb5, 0x31, 0xed, 0x1d, 0xf8, 0x9c, 0x90,
  0x04, 0xc2, 0x0c, 0x14, 0xb8, 0x43, 0x34, 0x8e, 0x10, 0x88, 0x12, 0xa3,
  0x9a, 0x9a, 0x86, 0xab, 0x98, 0x06, 0x65, 0x4f, 0x4a, 0x86, 0x00, 0x24,
  0x13, 0x01, 0x13, 0x03, 0x13, 0x02, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9,
  0xcc, 0xa8, 0xc0, 0x2c, 0xc0, 0x30, 0xc0, 0x0a, 0xc0, 0x09, 0xc0, 0x13,
  0xc0, 0x14, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0x00, 0x0a,
  0x01, 0x00, 0x01, 0x8f, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x28, 0x00, 0x00,
  0x25, 0x66, 0x69, 0x72, 0x65, 0x66, 0x6f, 0x78, 0x2e, 0x73, 0x65, 0x74,
  0x74, 0x69, 0x6e, 0x67, 0x73, 0x2e, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
  0x65, 0x73, 0x2e, 0x6d, 0x6f, 0x7a, 0x69, 0x6c, 0x6c, 0x61, 0x2e, 0x63,
  0x6f, 0x6d, 0x00, 0x17, 0x00, 0x00, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00,
  0x0a, 0x00, 0x0e, 0x00, 0x0c, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00,
  0x19, 0x01, 0x00, 0x01, 0x01, 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00, 0x00,
  0x23, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0b, 0x00, 0x09, 0x08, 0x68, 0x74,
  0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x00, 0x05, 0x00, 0x05, 0x01, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x33, 0x00, 0x6b, 0x00, 0x69, 0x00, 0x1d, 0x00,
  0x20, 0xc0, 0xab, 0xaa, 0x1f, 0xd2, 0x71, 0xdc, 0x6f, 0xc8, 0x7b, 0x4b,
  0x32, 0x65, 0xff, 0x51, 0x6c, 0x41, 0x07, 0xff, 0x9a, 0x9c, 0x54, 0x30,
  0x90, 0xbc, 0x42, 0xcf, 0x5d, 0xda, 0x3d, 0xd6, 0x57, 0x00, 0x17, 0x00,
  0x41, 0x04, 0x04, 0xbc, 0x09, 0x6a, 0x69, 0xf7, 0xc5, 0xda, 0xe6, 0x01,
  0x17, 0x9c, 0x43, 0x3d, 0x59, 0xa2, 0x78, 0xfc, 0x68, 0xeb, 0x31, 0x63,
  0x7a, 0x1c, 0xba, 0xdf, 0xe6, 0x3b, 0x9a, 0x88, 0x08, 0x36, 0x06, 0xcb,
  0xf5, 0xff, 0x08, 0x76, 0xcd, 0xb1, 0xb2, 0xdc, 0x19, 0x88, 0x1a, 0x9a,
  0x77, 0xaa, 0x4f, 0x93, 0x80, 0xdf, 0xf3, 0x7d, 0x03, 0x35, 0x63, 0x24,
  0x7c, 0x88, 0x72, 0x5c, 0xef, 0x30, 0x00, 0x2b, 0x00, 0x05, 0x04, 0x03,
  0x04, 0x03, 0x03, 0x00, 0x0d, 0x00, 0x18, 0x00, 0x16, 0x04, 0x03, 0x05,
  0x03, 0x06, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05,
  0x01, 0x06, 0x01, 0x02, 0x03, 0x02, 0x01, 0x00, 0x2d, 0x00, 0x02, 0x01,
  0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01, 0x00, 0x15, 0x00, 0x80, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

unsigned char client_hello_no_server_name_eth[] = {
  0x00, 0x26, 0x98, 0x0b, 0x01, 0x42, 0x3c, 0x08, 0xf6, 0xd8, 0xf0, 0xc7,
  0x08, 0x00, 0x45, 0x00, 0x01, 0x11, 0x4a, 0x96, 0x40, 0x00, 0x7c, 0x06,
  0x3a, 0xa4, 0x0a, 0x52, 0xd6, 0x87, 0x2c, 0xe0, 0x6a, 0xf3, 0xd6, 0x93,
  0x01, 0xbb, 0x60, 0xac, 0xd1, 0x8b, 0x5f, 0x9e, 0xb5, 0x50, 0x50, 0x18,
  0x01, 0x04, 0x1c, 0x92, 0x00, 0x00, 0x16, 0x03, 0x01, 0x00, 0xe4, 0x01,
  0x00, 0x00, 0xe0, 0x03, 0x03, 0x2a, 0x09, 0x12, 0xec, 0x90, 0x63, 0xdf,
  0x49, 0x4b, 0xe4, 0x01, 0xbf, 0x5e, 0xbb, 0x87, 0xa1, 0x12, 0x3f, 0xa0,
  0x44, 0x63, 0x74, 0x28, 0xc1, 0x85, 0xc8, 0xc3, 0x1a, 0xab, 0xa4, 0x41,
  0x4a, 0x20, 0xe8, 0x13, 0x57, 0xf1, 0xf9, 0xfd, 0x5d, 0x83, 0x5d, 0xb8,
  0x10, 0xe1, 0x2a, 0x01, 0xca, 0x92, 0x72, 0xb7, 0x8d, 0x0b, 0xe6, 0x87,
  0x90, 0x76, 0x82, 0x77, 0x56, 0xf0, 0x9a, 0x27, 0xb7, 0xe3, 0x00, 0x42,
  0xc0, 0x30, 0xc0, 0x2c, 0xc0, 0x28, 0xc0, 0x24, 0x00, 0xa5, 0x00, 0xa1,
  0x00, 0x9f, 0x00, 0x6b, 0x00, 0x69, 0x00, 0x68, 0xc0, 0x32, 0xc0, 0x2e,
  0xc0, 0x2a, 0xc0, 0x26, 0x00, 0x9d, 0x00, 0x3d, 0xc0, 0x2f, 0xc0, 0x2b,
  0xc0, 0x27, 0xc0, 0x23, 0x00, 0xa4, 0x00, 0xa0, 0x00, 0x9e, 0x00, 0x67,
  0x00, 0x3f, 0x00, 0x3e, 0xc0, 0x31, 0xc0, 0x2d, 0xc0, 0x29, 0xc0, 0x25,
  0x00, 0x9c, 0x00, 0x3c, 0x00, 0xff, 0x01, 0x00, 0x00, 0x55, 0x00, 0x0b,
  0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0a, 0x00, 0x1c, 0x00, 0x1a,
  0x00, 0x17, 0x00, 0x19, 0x00, 0x1c, 0x00, 0x1b, 0x00, 0x18, 0x00, 0x1a,
  0x00, 0x16, 0x00, 0x0e, 0x00, 0x0d, 0x00, 0x0b, 0x00, 0x0c, 0x00, 0x09,
  0x00, 0x0a, 0x00, 0x23, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e,
  0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03,
  0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03,
  0x02, 0x01, 0x02, 0x02, 0x02, 0x03, 0x00, 0x0f, 0x00, 0x01, 0x01
};

unsigned char unlabeled_data[] = {
  0x00, 0x26, 0x98, 0x0b, 0x01, 0x42, 0x00, 0x23, 0xac, 0x67, 0xb6, 0x41,
  0x08, 0x00, 0x45, 0x00, 0x01, 0x3d, 0x9e, 0x7d, 0x40, 0x00, 0x3e, 0x06,
  0xb9, 0x64, 0x40, 0x66, 0xff, 0x28, 0x40, 0x44, 0x64, 0x06, 0xf0, 0x57,
  0x01, 0xbb, 0xef, 0xd3, 0xc2, 0x62, 0x7a, 0x26, 0x64, 0x19, 0x50, 0x18,
  0x10, 0x12, 0xcd, 0x86, 0x00, 0x00, 0x16, 0x03, 0x01, 0x01, 0x10, 0x01,
  0x00, 0x01, 0x0c, 0x03, 0x03, 0x59, 0x97, 0x6f, 0xb2, 0x0f, 0x5b, 0xeb,
  0xad, 0xc5, 0x4c, 0xa2, 0xdf, 0xb0, 0x7d, 0x96, 0xea, 0x71, 0xbf, 0x8c,
  0x83, 0xcb, 0xf6, 0xda, 0x88, 0x8c, 0xf9, 0xb4, 0x3d, 0x74, 0x44, 0x77,
  0x5f, 0x00, 0x00, 0x70, 0xc0, 0x2f, 0xc0, 0x2b, 0xc0, 0x30, 0xc0, 0x2c,
  0x00, 0x9e, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x28, 0x00, 0x6b, 0x00, 0xa3,
  0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0xaf, 0xc0, 0xad,
  0xc0, 0xa3, 0xc0, 0x9f, 0xc0, 0x5d, 0xc0, 0x61, 0xc0, 0x57, 0xc0, 0x53,
  0x00, 0xa2, 0xc0, 0xae, 0xc0, 0xac, 0xc0, 0xa2, 0xc0, 0x9e, 0xc0, 0x5c,
  0xc0, 0x60, 0xc0, 0x56, 0xc0, 0x52, 0xc0, 0x24, 0x00, 0x6a, 0xc0, 0x23,
  0x00, 0x40, 0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0x00, 0x38, 0xc0, 0x09,
  0xc0, 0x13, 0x00, 0x33, 0x00, 0x32, 0x00, 0x9d, 0xc0, 0xa1, 0xc0, 0x9d,
  0xc0, 0x51, 0x00, 0x9c, 0xc0, 0xa0, 0xc0, 0x9c, 0xc0, 0x50, 0x00, 0x3d,
  0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff, 0x01, 0x00, 0x00, 0x73,
  0x00, 0x00, 0x00, 0x17, 0x00, 0x15, 0x00, 0x00, 0x12, 0x69, 0x64, 0x62,
  0x72, 0x6f, 0x6b, 0x65, 0x72, 0x2e, 0x77, 0x65, 0x62, 0x65, 0x78, 0x2e,
  0x63, 0x6f, 0x6d, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00,
  0x0a, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00,
  0x19, 0x00, 0x18, 0x00, 0x23, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00,
  0x17, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x30, 0x00, 0x2e, 0x04, 0x03, 0x05,
  0x03, 0x06, 0x03, 0x08, 0x07, 0x08, 0x08, 0x08, 0x09, 0x08, 0x0a, 0x08,
  0x0b, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06,
  0x01, 0x03, 0x03, 0x02, 0x03, 0x03, 0x01, 0x02, 0x01, 0x03, 0x02, 0x02,
  0x02, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02
};


// end of packet data

typedef void (*dummy_func)();

int verbosity = 0;
char * default_resources_path = "../resources/resources.tgz";

const char * path_to_libmerc_library = "../src/libmerc/libmerc.so";

struct libmerc_api {

    libmerc_api(const char *lib_path) {
        if (bind(lib_path) != 0) {
            throw std::runtime_error("error: could not initialize libmerc_api");
        }
    }

    ~libmerc_api() {
        mercury_unbind(*this);
    }

    decltype(mercury_init)                                  *init = nullptr;
    decltype(mercury_finalize)                              *finalize = nullptr;
    decltype(mercury_packet_processor_construct)            *packet_processor_construct = nullptr;
    decltype(mercury_packet_processor_destruct)             *packet_processor_destruct = nullptr;
    decltype(mercury_packet_processor_get_analysis_context) *get_analysis_context = nullptr;
    decltype(analysis_context_get_fingerprint_type)         *get_fingerprint_type = nullptr;
    decltype(analysis_context_get_fingerprint_status)       *get_fingerprint_status = nullptr;
    decltype(analysis_context_get_process_info)             *get_process_info = nullptr;
    decltype(analysis_context_get_malware_info)             *get_malware_info = nullptr;
    decltype(mercury_write_stats_data)                      *write_stats_data = nullptr;

    void *dl_handle = nullptr;

    int bind(const char *lib_path) {

        if ((dl_handle = dlopen(lib_path, RTLD_LAZY|RTLD_LOCAL)) == nullptr) {
            const char *dlerr = dlerror();
            fprintf(stderr, "mercury: failed to load %s: %s\n", lib_path, dlerr ? dlerr : "unknown error");
            return -1; // error
        } else {
            fprintf(stderr, "mercury: loading %s\n", lib_path);
        }

        init =                       (decltype(init))                       dlsym(dl_handle, "mercury_init");
        finalize =                   (decltype(finalize))                   dlsym(dl_handle, "mercury_finalize");
        packet_processor_construct = (decltype(packet_processor_construct)) dlsym(dl_handle, "mercury_packet_processor_construct");
        packet_processor_destruct =  (decltype(packet_processor_destruct))  dlsym(dl_handle, "mercury_packet_processor_destruct");
        get_analysis_context =       (decltype(get_analysis_context))       dlsym(dl_handle, "mercury_packet_processor_get_analysis_context");
        get_fingerprint_type =       (decltype(get_fingerprint_type))       dlsym(dl_handle, "analysis_context_get_fingerprint_type");
        get_fingerprint_status =     (decltype(get_fingerprint_status))     dlsym(dl_handle, "analysis_context_get_fingerprint_status");
        get_process_info =           (decltype(get_process_info))           dlsym(dl_handle, "analysis_context_get_process_info");
        get_malware_info =           (decltype(get_malware_info))           dlsym(dl_handle, "analysis_context_get_malware_info");
        write_stats_data =           (decltype(write_stats_data))           dlsym(dl_handle, "mercury_write_stats_data");

        if (init                       == nullptr ||
            finalize                   == nullptr ||
            packet_processor_construct == nullptr ||
            packet_processor_destruct  == nullptr ||
            get_analysis_context       == nullptr ||
            get_fingerprint_type       == nullptr ||
            get_fingerprint_status     == nullptr ||
            get_process_info           == nullptr ||
            get_malware_info           == nullptr ||
            write_stats_data           == nullptr) {
            fprintf(stderr, "error: could not initialize one or more libmerc function pointers\n");
            return -1;
        }
        return 0;

        fprintf(stderr, "mercury_bind() succeeded with handle %p\n", dl_handle);

        return 0; // success
    }

    void mercury_unbind(struct libmerc_api &libmerc_api) {
        dlclose(libmerc_api.dl_handle);
        libmerc_api.dl_handle = nullptr;
    }

};


// The function fprint_analysis_context() prints out all of the
// information available about an analysis context.  It is an example
// of how the libmerc.h interface can be used.  It makes more calls
// that are necessary, to illustrate how the library responds.  In
// particular, if the analysis_context is NULL, then it is unnecessary
// to call any other functions, and if fingerprint_type is
// fingerprint_type_unknown, then it is unnecessary to call
// analysis_context_get_fingerprint_string().
//
void fprint_analysis_context(FILE *f,
                             const struct libmerc_api *merc,
                             const struct analysis_context *ctx) {

    fprintf(f, "---------- start of %s ----------\n", __func__);
    if (ctx == NULL) {
        fprintf(f, "null analysis_context (no analysis present)\n");
    }
    enum fingerprint_type type = analysis_context_get_fingerprint_type(ctx);
    if (type == fingerprint_type_tls) {
        fprintf(f, "fingerprint_type: tls\n");
    } else if (type == fingerprint_type_unknown) {
        fprintf(f, "fingerprint_type: unknown\n");
    } else {
        fprintf(f, "fingerprint_type: not tls (type code %u)\n", type);
    }
    const char *fp_string = analysis_context_get_fingerprint_string(ctx);
    if (fp_string) {
        fprintf(f, "fingerprint_string: %s\n", fp_string);
    } else {
        fprintf(f, "fingerprint_string: not present (null)\n");
    }
    enum fingerprint_status fp_status = analysis_context_get_fingerprint_status(ctx);
    if (fp_status == fingerprint_status_labeled) {
        fprintf(f, "fingerprint_status: labeled\n");
    } else if (fp_status == fingerprint_status_unlabled) {
        fprintf(f, "fingerprint_status: unlabeled\n");
    } else if (fp_status == fingerprint_status_randomized) {
        fprintf(f, "fingerprint_status: randomized\n");
    } else if (fp_status == fingerprint_status_no_info_available) {
        fprintf(f, "fingerprint_status: no info available\n");
    } else {
        fprintf(f, "fingerprint_status: unknown status code (%d)\n", fp_status);
    }

    const char *server_name = analysis_context_get_server_name(ctx);
    if (server_name) {
        fprintf(f, "server_name: %s\n", server_name);
    } else {
        fprintf(f, "server_name: not present (null)\n");
    }
    const char *probable_process = NULL;
    double probability_score = 0.0;
    if (merc->get_process_info(ctx,
                               &probable_process,
                               &probability_score)) {
        fprintf(f,
                "probable_process: %s\tprobability_score: %f\n",
                probable_process,
                probability_score);
    }
    bool probable_process_is_malware = false;
    double probability_malware = 0.0;
    if (merc->get_malware_info(ctx,
                               &probable_process_is_malware,
                               &probability_malware)) {
        fprintf(f,
                "probable_process_is_malware: %s\tprobability_malware: %f\n",
                probable_process_is_malware ? "true" : "false",
                probability_malware);
    }
    fprintf(f, "----------  end of %s  ----------\n", __func__);
}

struct packet_processor_state {
    unsigned int thread_number;
    struct libmerc_api *mercury;
    mercury_context mc;

    packet_processor_state(unsigned int tn, struct libmerc_api *m, mercury_context c) : thread_number{tn}, mercury{m}, mc{c} {}

};

mercury_context initialize_mercury(libmerc_config& config) {
    // bind libmerc
    libmerc_api mercury(path_to_libmerc_library);
    
    // init mercury
    mercury_context mc = mercury.init(&config, verbosity);

    return mc;
}

libmerc_config create_config(bool dns_json_output = false,
                             bool certs_json_output = false,
                             bool metadata_output = false,
                             bool do_analysis = true,
                             bool do_stats = true,
                             bool report_os = false,
                             bool output_tcp_initial_data = false,
                             bool output_udp_initial_data = false,
                             char *resources = default_resources_path,
                             const uint8_t * enc_key = NULL,
                             enc_key_type key_type = enc_key_type_none,
                             char *packet_filter_cfg = NULL,
                             float fp_proc_threshold = 0.0,
                             float proc_dst_threshold = 0.0,
                             size_t max_stats_entries = 0) 
{
    libmerc_config config{};     
    
    config.dns_json_output = dns_json_output;
    config.do_analysis = do_analysis;
    config.do_stats = do_stats;
    config.enc_key = enc_key;
    config.fp_proc_threshold = fp_proc_threshold;
    config.key_type = key_type;
    config.max_stats_entries = max_stats_entries;
    config.metadata_output = metadata_output;
    config.output_tcp_initial_data = output_tcp_initial_data;
    config.output_udp_initial_data = output_udp_initial_data;
    config.packet_filter_cfg = packet_filter_cfg;
    config.proc_dst_threshold = proc_dst_threshold;
    config.report_os = report_os;
    config.resources = resources;
    return config;
}

void check_global_configuraton(mercury_context &mc, libmerc_config &config) {
    //check correctness of config set
    CHECK(mc->global_vars.dns_json_output == config.dns_json_output);
    CHECK(mc->global_vars.do_analysis == config.do_analysis);
    CHECK(mc->global_vars.do_stats == config.do_stats);
    CHECK(mc->global_vars.enc_key == config.enc_key);
    CHECK(mc->global_vars.fp_proc_threshold == config.fp_proc_threshold);
    CHECK(mc->global_vars.key_type == config.key_type);
    CHECK(mc->global_vars.max_stats_entries == config.max_stats_entries);
    CHECK(mc->global_vars.metadata_output == config.metadata_output);
    CHECK(mc->global_vars.output_tcp_initial_data == config.output_tcp_initial_data);
    CHECK(mc->global_vars.output_udp_initial_data == config.output_udp_initial_data);
    CHECK(mc->global_vars.packet_filter_cfg == config.packet_filter_cfg);
    CHECK(mc->global_vars.proc_dst_threshold == config.proc_dst_threshold);
    CHECK(mc->global_vars.report_os == config.report_os);
    CHECK(mc->global_vars.resources == config.resources);
}

void *packet_processor(void *arg) {
    packet_processor_state *pp = (packet_processor_state *)arg;
    struct libmerc_api *merc = pp->mercury;
    struct timespec time;
    time.tv_sec = time.tv_nsec = 0;  // set to January 1st, 1970 (the Epoch)

    // fprintf(stderr, "packet_processor() has libmerc_api=%p and mercury_context=%p\n", (void *)merc, (void *)pp->mc);

    // create mercury packet processor
    mercury_packet_processor mpp = merc->packet_processor_construct(pp->mc);
    if (mpp == NULL) {
        fprintf(stderr, "error in mercury_packet_processor_construct()\n");
        return NULL;
    }

    // get analysis result and write it out
    //
    const struct analysis_context *ctx = merc->get_analysis_context(mpp, client_hello_eth, client_hello_eth_len, &time);
    fprintf(stderr, "\nanalyzing TLS client hello\n");
    fprint_analysis_context(stderr, merc, ctx);

    // try it on another packet
    //
    ctx = merc->get_analysis_context(mpp, client_hello_no_server_name_eth, sizeof(client_hello_no_server_name_eth), &time);
    fprintf(stderr, "\nanalyzing TLS client hello without server name\n");
    fprint_analysis_context(stderr, merc, ctx);

    // try it on a packet with an unlabeled fingerprint
    //
    ctx = merc->get_analysis_context(mpp, unlabeled_data, sizeof(unlabeled_data), &time);
    fprintf(stderr, "\nanalyzing TLS client hello with an unlabeled fingerprint\n");
    fprint_analysis_context(stderr, merc, ctx);

    // try it on a tcp syn packet
    //
    ctx = merc->get_analysis_context(mpp, tcp_syn, sizeof(tcp_syn), &time);
    fprintf(stderr, "\nanalyzing TCP SYN packet\n");
    fprint_analysis_context(stderr, merc, ctx);

    // pass null analysis_context
    //
    fprintf(stderr, "\nanalyzing NULL context\n");
    fprint_analysis_context(stderr, merc, nullptr);

    // destroy packet processor
    merc->packet_processor_destruct(mpp);

    return NULL;
}

int test_libmerc(const struct libmerc_config *config, int verbosity, bool fail=false) {
    int num_loops = 4;
    constexpr int num_threads = 8;

    for (int i = 0; i < num_loops; i++) {
        fprintf(stderr, "loop: %d\n", i);

        // bind libmerc
        libmerc_api mercury("../src/libmerc/libmerc.so");

        // init mercury
        mercury_context mc = mercury.init(config, verbosity);
        if (mc == NULL) {
            fprintf(stderr, "error: mercury_init() returned null\n");
            return -1;
        }

        // create packet processing threads
        std::array<pthread_t, num_threads> tid_array;
        packet_processor_state thread_state[num_threads] = {
             { 0, &mercury, mc },
             { 1, &mercury, mc },
             { 2, &mercury, mc },
             { 3, &mercury, mc },
             { 4, &mercury, mc },
             { 5, &mercury, mc },
             { 6, &mercury, mc },
             { 7, &mercury, mc }
            };
        //std::array<unsigned int, num_threads> thread_number = { 0, 1, 2, 3, 4, 5, 6, 7 };
        for (int idx=0; idx < num_threads; idx++) {
            pthread_create(&tid_array[idx], NULL, packet_processor, &thread_state[idx]);
        }
        fprintf(stderr, "created all %zu threads\n", tid_array.size());

        if (fail) {
            // delete mercury state, to force failure
            mercury.finalize(mc);
        }

        for (auto & t : tid_array) {
            pthread_join(t, NULL);
        }
        fprintf(stderr, "joined all %zu threads\n", tid_array.size());

        // write stats file
        mercury.write_stats_data(mc, "libmerc_driver_stats.json.gz");

        // destroy mercury
        mercury.finalize(mc);

        fprintf(stderr, "completed mercury_finalize()\n");

        // mercury is unbound from its shared object file when it leaves scope

    }

    return 0;
}

int double_bind_test(const struct libmerc_config *config, const struct libmerc_config *config2) {
    int verbosity = 1;
    int num_loops = 4;
    constexpr int num_threads = 8;

    fprintf(stderr, "running mercury_double_bind() test\n");

    for (int i = 0; i < num_loops; i++) {
        fprintf(stderr, "loop: %d\n", i);

        // bind libmerc
        libmerc_api mercury("../src/libmerc/libmerc.so");

        // init mercury
        mercury_context mc = mercury.init(config, verbosity);
        if (mc == nullptr) {
            fprintf(stderr, "error: mercury_init() returned null\n");
            return -1;
        }

        // bind and init second mercury library
        struct libmerc_api mercury_alt("../src/libmerc/libmerc.so.alt");
        mercury_context mc_alt = mercury_alt.init(config2, verbosity);
        if (mc_alt == nullptr) {
            fprintf(stderr, "error: mercury_init() returned null in second init\n");
            mercury.finalize(mc);
            return -1;
        }

        // create packet processing threads
        std::array<pthread_t, num_threads> tid_array;
        packet_processor_state thread_state[num_threads] = {
             { 0, &mercury, mc },
             { 1, &mercury, mc },
             { 2, &mercury, mc },
             { 3, &mercury, mc },
             { 4, &mercury_alt, mc_alt },
             { 5, &mercury_alt, mc_alt },
             { 6, &mercury_alt, mc_alt },
             { 7, &mercury_alt, mc_alt }
            };
        for (int idx=0; idx < num_threads; idx++) {
            pthread_create(&tid_array[idx], NULL, packet_processor, &thread_state[idx]);
        }
        fprintf(stderr, "created all %zu threads\n", tid_array.size());

        mercury.write_stats_data(mc, "libmerc_driver_stats_pre_join.json.gz");
        mercury.write_stats_data(mc_alt, "libmerc_driver_stats_pre_join_alt.json.gz");

        for (auto & t : tid_array) {
            pthread_join(t, NULL);
        }
        fprintf(stderr, "joined all %zu threads\n", tid_array.size());

        // write stats file
        mercury.write_stats_data(mc, "libmerc_driver_stats_post_join.json.gz");
        mercury.write_stats_data(mc_alt, "libmerc_driver_stats_post_join_alt.json.gz");

        // destroy mercury
        mercury.finalize(mc);

        fprintf(stderr, "completed mercury_finalize()\n");

        // mercury and mercury_alt are unbound from its shared object
        // file when they leave scope

        mercury_alt.finalize(mc_alt);

    }

    return 0;
}

TEST_CASE("double_bind_test") {  
    libmerc_config config = create_config();
    libmerc_config config_lite = create_config(); // note: just different, not really lite

    // perform double bind/init test
    int retval = double_bind_test(&config_lite, &config);
    REQUIRE_FALSE(retval);
}

TEST_CASE("flow_test") {
    // initialize libmerc's global configuration by creating a
    // libmerc_config structure and then passing it into mercury_init
    libmerc_config config = create_config();

    libmerc_config config_lite = create_config(); // note: just different, not really lite

    int retval = test_libmerc(&config, verbosity);
    REQUIRE_FALSE(retval);

    retval = test_libmerc(&config_lite, verbosity);
    REQUIRE_FALSE(retval);

    // repeat test with original config
    retval = test_libmerc(&config, verbosity);
    REQUIRE_FALSE(retval);
}



//TODO: make a scenario
TEST_CASE("check_global_vars_configuration") {
    libmerc_config config = create_config();
    
    // init mercury
    mercury_context mc = initialize_mercury(config);
    REQUIRE(mc != nullptr);

    check_global_configuraton(mc, config);


}

SCENARIO("test_mercury_init") {
    GIVEN("mecrury config") {
        libmerc_config config = create_config();
    
        WHEN("After initialize") {
            THEN("merciry initialized ") {
                mercury_context mc = initialize_mercury(config);
                REQUIRE(mc != nullptr);
            }
        }

        // WHEN("Set resources to nullptr") { /*failed: mercury context created in this case*/
        //     config.resources = nullptr;
        //     THEN("Cannot initialize mercury context: return nullptr") {
        //         REQUIRE(mercury_init(&config, verbosity) == nullptr);
        //     }
        // }

        WHEN("Set resources to empty") {
            config.resources = (char *) "";
            THEN("Cannot initialize mercury context: return nullptr") {
                REQUIRE(mercury_init(&config, verbosity) == nullptr);
            }
        }
    }
}

SCENARIO("test_mercury_finalize") {
    GIVEN("mecrury context") {
        libmerc_config config = create_config();
    
        // init mercury
        mercury_context mc = initialize_mercury(config);

        WHEN("After initialize") {
            THEN("merciry initialized ") {
                REQUIRE(mc != nullptr);
            }
        }

        WHEN("Finish") {
            THEN("Correct finilize: return 0") {
                REQUIRE(mercury_finalize(mc) == 0);
            }
        }

        // WHEN("Finish two times") { /*failed: facing exception instead of -1, because mc deleted but pointer not nullptr*/
        //     THEN("Incorrect behaviour: return -1") {
        //         REQUIRE(mercury_finalize(mc) == 0);
        //         CHECK(mc == nullptr);
        //         //CHECK(mc->global_vars.certs_json_output == false); /*exception as memory under pointer already dealocated*/
        //         //CHECK(mercury_finalize(mc) == -1);  /*check in ~mercury() also needed*/
        //     }
        // }
    }  
}

SCENARIO("test_packet_processor_construct") {
    GIVEN("mercury context") {
        libmerc_config config = create_config();
        mercury_context mc = initialize_mercury(config);
        WHEN("Mercury context is correct") {
            THEN("packet processor created") {
                auto mpp = mercury_packet_processor_construct(mc);
                REQUIRE(mpp != NULL);

                /*avoid memory leaks*/
                mercury_packet_processor_destruct(mpp);
            }
        }

        // WHEN("Mercury context is finalized") { /*failed: no check for mercury_context is nullptr*/
        //      mercury_finalize(mc);
        //      THEN("packet processor set to NULL") {
        //          REQUIRE(mercury_packet_processor_construct(mc) == NULL);
        //      }
        // }

        WHEN("mercury classifier is nullptr") {
            delete mc->c; /*avoid memory leaks*/ 
            mc->c = nullptr;
            THEN("packet processor set to NULL") {
                auto mpp = mercury_packet_processor_construct(mc);
                REQUIRE(mpp == NULL);
            }
        }

        WHEN("mercury classifier is nullptr and analysis isn`t needed") {
            delete mc->c; /*avoid memory leaks*/
            mc->c = nullptr;
            mc->global_vars.do_analysis = false;
            THEN("packet processor created") {
                auto mpp = mercury_packet_processor_construct(mc);
                REQUIRE(mpp != NULL);

                /*avoid memory leaks*/
                mercury_packet_processor_destruct(mpp);
            }
        }

        //TODO: WHEN("Do_stats and message queue is empty") {}
    }
}

SCENARIO("test_packet_processor_destruct") {
    GIVEN("packet processor") {
        libmerc_config config = create_config();
        mercury_context mc = initialize_mercury(config);
        mercury_packet_processor mpp = mercury_packet_processor_construct(mc);

        WHEN("destruct packet processor") {
            THEN("no throws catched") {
                REQUIRE_NOTHROW(mercury_packet_processor_destruct(mpp));
            }
        }  

        // WHEN("destruct twice") {
        //     THEN("throws catched") {
        //         REQUIRE_NOTHROW(mercury_packet_processor_destruct(mpp));
        //         REQUIRE_THROWS(mercury_packet_processor_destruct(mpp));
        //     }
        // }

        // WHEN("packet processor is nullptr") { /*failed: no exception. memory leak*/
        //     mpp = nullptr;
        //     THEN("throws catched") {
        //         REQUIRE_THROWS(mercury_packet_processor_destruct(mpp));
        //     }
        // } 
    }
}

SCENARIO("test_write_stats_data") {
    GIVEN("mercury context and stats file") {
        libmerc_config config = create_config();
        config.packet_filter_cfg = "tls";
        mercury_context mc = initialize_mercury(config);
        char * stats_file = "merc_stats_0.json.gz";

        WHEN("") {
            THEN("write stats file") {
                REQUIRE(mercury_write_stats_data(mc, stats_file));
            }
        }

        WHEN("mercury context is null") {
            THEN("codn`t write stats file") {
                REQUIRE_FALSE(mercury_write_stats_data(nullptr, stats_file));
            }
        }

       /* WHEN("mercury finalized") { //seg fault
            mercury_finalize(mc);
            THEN("couldn`t write stats file") {
                REQUIRE_FALSE(mercury_write_stats_data(mc, stats_file));
            }
        }*/

        WHEN("empty stats file name") {
            THEN("couldn`t write stats file") {
                REQUIRE_FALSE(mercury_write_stats_data(mc, ""));
            }
        }

        WHEN("stats file is null") {
            stats_file = nullptr;
            THEN("couldn`t write stats file") {
                REQUIRE_FALSE(mercury_write_stats_data(mc, stats_file));
            }
        }
    }
}

SCENARIO("test packet_processor_get_analysis_context") {
    GIVEN("mercury packet processor") {
        libmerc_config config = create_config();
        mercury_context mc = initialize_mercury(config);
        mercury_packet_processor mpp = mercury_packet_processor_construct(mc);

        struct timespec time;
        time.tv_sec = time.tv_nsec = 0;  // set to January 1st, 1970 (the Epoch)
        WHEN("get analysis context") {
            mercury_packet_processor_get_analysis_context(mpp, nullptr, 0, &time);
            THEN("not a valid result") {
                REQUIRE_FALSE(mpp->analysis.result.is_valid());

                mercury_packet_processor_destruct(mpp);
            }
        }

        // WHEN("get analysis context") {
        //     mercury_packet_processor_get_analysis_context(mpp, tcp_syn, sizeof(tcp_syn), &time);
        //     THEN("a valid result  exist") {
        //         REQUIRE(mpp->analysis.result.is_valid());
        //     }
        // }
    }
}

