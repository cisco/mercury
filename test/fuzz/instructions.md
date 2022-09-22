# Fuzz Testing Guide

This guide aims at writing and running a targeted fuzz test case.

## Overview

A particular fuzz test can cover a specific class/struct or a code snippet focused on a specific operation. Each testcase 
comprises of a fuzz test function and one or more seed files. All fuzz test functions declarations (or definitions) must be exposed in a header file {pre-existing or new} in [this dir](../../src/libmerc).
For a targeted fuzz test for a {class_name/struct_name/snippet_name}, below are the naming conventions and directory structure.

## Test naming convention

The fuzz-test function name follows the rule : {class_name/struct_name/snippet_name}_fuzz_test. Each test case and related code snippet needs to be added in an anonymous namespace.   
```
namespace {
    test_function(){}
};
```
for e.g. look here [quic_init_fuzz_test](../../src/libmerc/quic.h).

## Test case directory

Each fuzz-test has a corresponding test case directory in [this dir](.) . The test directory name should be {class_name/struct_name/snippet_name}, same as what was used in the test-case function name, less {_fuzz_test}.

## Test case directory structure

(with e.g.)
```
[this dir](.)
    |
    |
    |
     ->[test case](./quic_init/)
            |
            |
            |
             ->[seed dir](./quic_init/corpus/)
                    |
                    |
                    |
                     ->[seed{s}](./quic_init/corpus/seed_1)
```

                                      
## Seed format

Each seed file contains expected input for the corresponding test case({class_name/struct_name/snippet_name}), which may be raw packet bytes or processed bytes. The files may contain ASCII in case every bytes is ASCII printable or a raw hexdump in case the input contains non-ASCII printable characters.    

To generate a seed file, dump the hex bytes in a file with format "FF FF FF ..." and then do    
```
xxd -r -p hex_file seed
```


## Running fuzz-test

The complete fuzz-test can be run by issuing "make fuzz-test" in [this dir](../).


## Running specific test-case

A specific test case test_name{class_name/struct_name/snippet_name} can be run by issuing the following command in [this dir](.)    
"[test_script](./generate_fuzz_test.sh) {-r <iterations> -t <time> -h <help> -n <none(run all test)/test_name>}".   
e.g.
```
"./generate_fuzz_test.sh -n ssdp -t 200 -r 1000000000"    
```