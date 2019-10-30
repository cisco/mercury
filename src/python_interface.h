/*
 * python_interface.h
 *
 * Copyright (c) 2019 Cisco Systems, Inc. All rights reserved.  License at
 * https://github.com/cisco/mercury/blob/master/LICENSE
 */

#ifndef PYTHON_INTERFACE_H
#define PYTHON_INTERFACE_H

#include <pthread.h>
#include <string>
#include <time.h>
#include <Python.h>
#include <string>
#include <iostream>
#include <sstream>
#include <map>
#include <unordered_map>
#include <utility>

int init_python();

int finalize_python();

void py_process_detection(char **results,
                          char *fp_string,
                          char *sni,
                          char *dst_addr_string,
                          int dest_port);

#endif /* PYTHON_INTERFACE_H */
