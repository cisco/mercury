# Auto-generating C++ Code from Assigned Number CSV Files

Network protocols are full of numbers that have a special meaning. For instance, 6 means TCP and 17 means UDP, in the protocol field of Internet Protocol (IP) packets.  These special values are called assigned numbers.  When they indicate a data type or message format, they are often called type codes, or code points.  When they indicate a protocol, they are sometimes called protocol numbers.  For most Internet protocols, these numbers are managed by the Internet Assigned Numbers Authority ([IANA](https://www.iana.org/protocols)), which provides these assignments in human and machine readable formats. There is a vast multitude of assigned numbers.

To minimize the amount of C++ code that must be written in order to handle assigned numbers, the mercury package includes a utility `csv` and makefile that can automatically generate classes that represent assigned numbers from Comma Separated Value (CSV) files in the IANA format.  This document describes how to use the capability to (re)build those classes, and how to use those classes when developing a new protocol.

The goals of the auto-generation system are:

* to minimize the amount of tedious and error-prone manual work involved in implementing protocols,
  
* to provide a uniform programmatic interface and JSON output syntax for different assigned numbers, and
  
* to have tooling that can be re-run in the future so that new assigned number values can be easily brought into the software
  once they are registered with IANA,
  
* to track assigned numbers that are not registered with IANA, and be able to combine this information with IANA data.

We used the following approach.  Each assigned number is represented by a single C++ class, which is generated from one or more CSV files, using the `csv` utility.  A Makefile controls the downloading of CSV files from IANA files, and the running of `csv`, to create a single C++ header-only library that includes all of the assigned number classes for a particular protocol.  The `wget` utility is used for downloading files.  The resulting protocol library header file is written into the `src/tables/` subdirectory; it must be manually copied into the `src/libmerc` subdirectory to be used in mercury.  Any protocol library used in mercury must be copied into that directory and committed into the mercury git repo, so that it doesn’t need to be auto-generated for each build.

## (Re)Building Tables

To use it, change your working directory to `rc/tables` and run `make`.  The default makefile target builds the `csv` utility, checks for new versions of IANA CSV files, downloads any such files into the `source/` subdirectory, and then builds the protocol library targets if the CSV files needed for a library are newer than the library itself.  The resulting library files are written into the `source/` subdirectory.

The `make clean` target removes the downloaded CSV files from the `source/` directory.  Any file with a name that matches the pattern `source/local*` will *not* be deleted; this naming convention can be used for files that hold non-standard assigned numbers, such as `source/local-stun-attributes.csv`.

The `make distclean` target runs `make clean` and then removes the protocol library files.  This target is run when the `make distclean` target is invoked in the root or `src/` directories of the mercury package.

## Using the csv utility

The `csv` utility reads one more CSV files, and writes out a single C++ header file that implements one or more classes, based on options passed in on the command line.   The formats of the commands are as follows.

To generate a class from the files in the comma-separated list `file_list`, with class name `class_name`, and the name `json_name` in the JSON output key, use the command with the form

```bash
file_list:class_name[:json_name]
```

The `json_name` is optional, but the `file_list` and `class_name` are mandatory.  If the `json_name` is not provided, then the JSON output uses `class_name` as the key.  For instance, the command

```bash
local-stun-attributes.csv,stun-parameters-4.csv:attribute_type:type
```

uses the files `local-stun-attributes.csv` and `stun-parameters-4.csv` to generate a class with the name `attribute_type` and the JSON output name of `type`.   If the `json_name` had not been provided, then the JSON output would have used the key `attribute_type`.

To include multiple assigned number classes in a single output file, there must be a separate command for each class.

Other commands are

- `output=filename` causes output to be written to the file `filename`, in the current working directory.
- `verbose=true` causes informative messages to be written to the standard error.
- `dir=directory_name` specifies that the input files are in the directory `directory_name`.

### Working with CSV files

The following simple example shows how `csv` works.  It uses the file `source/local-example.csv`, whose contents are

```csv
Value,Name,Reference
0x00,Reserved,
0x01,Request,
0x02,Response,
0x03-0xff,Unassigned,
```

As with the IANA conventions, the cells in the first line describes the data in their columns.  The last cell in the other lines are empty, which is acceptable, although each line must have the same number of cells. 

Let's run `csv` on that file, from the `src/tables` directory, and write the output into `example.h`:

```bash
$ ./csv outfile=example.h verbose=true dir=source local-example.csv:example
note: in class example: removing (Reserved, 0x0000)
note: in class example: removing (Unassigned, 0x0003-0x00ff)
```

The notices tell us that the `Reserved` and `Unassigned` entries are not considered assigned numbers.

Next, let's look at the output file:

```c++
// example.h
//
// this file was autogenerated at 2022-10-20T16:00:54Z
// you should edit the source file(s) instead of this one
//
// source files:
//     local-example.csv
//

#ifndef EXAMPLE_H
#define EXAMPLE_H

template <typename T>
class example : public encoded<T> {
    static_assert(std::is_unsigned_v<T>, "T must be an unsigned integer");
public:
    void write_json(json_object &o) const {
        const char *name = get_name();
        if (name == nullptr) {
            o.print_key_unknown_code("example", encoded<T>::value());
        } else {
            o.print_key_string("example", name);
        }
    }
    enum code {
        Request  = 0x0001,
        Response = 0x0002,
    };
    const char *get_name() const {
        switch(encoded<T>::value()) {
        case Request:  return "Request";
        case Response: return "Response";
        default:
            ;
        }
        return nullptr;
    }
};


#endif // EXAMPLE_H
```

The enumerations can be used programmaticly, for instance as `example::code::request`.  The class can be used in a protocol format, since they are derived from `class encoded<>`, and writing JSON output from an object of this class is as simple as invoking its `write_json()` member function.

### Naming Conventions

The `csv` utility processes second column of the CSV files to generate the strings that are used as enumeration types and output strings.  This processing is needed to ensure that the enumeration types are valid C++ names, and that the output strings are as readable as possible.  Spaces, tabs, parenthesis, and square braces are converted into underscores, and runs of multiple underscores are reduced down to a single underscore, and trailing underscores are deleted.  If the resulting string starts with a digit, then the enumeration type will start with an underscore.   For instance, if the output string is`256_bit_random_ECP_group`, then the corresponding enumeration will be `_256_bit_random_ECP_group` .  Otherwise, the enumerations match the output string.

## Limitations and Future Work

As implemented, the `csv` utility provides minimal error reporting.  Users deserve better feedback.

When working with additional protocols, it may be necessary to tweak the code to handle slightly different CSV file conventions.

One important limitation of the current system is that ranges (such as 0x03-0xff) are not handled.  A future version could add provide the information about what range a number is in through the `get_name()`member function, or a new member function. 

Additional information about a number could be provided through additional member functions.  The RFC numbers associated with most IANA registrations could be used to determine the year that a protocol option was standardized, and this information could be provided through a member function.   The range of years associated with the assigned numbers in a protocol message give a strong indication of the year that the implementation was completed.   Another useful bit of information is the RFC reference itself, which could be provided as a URL to facilitate quick lookups.  

There are well-known addresses that are managed by IANA, which could be handled as assigned numbers.  

Well-known ports could also be handled as assigned numbers, though implementations often use nonstandard destination ports, and IANA registrations should be taken with a grain of salt.

Some protocols (like HTTP) use *assigned strings* instead of assigned numbers (like GET, POST, and the many other [methods registered with IANA](https://www.iana.org/assignments/http-methods/http-methods.xhtml))).  Supporting assigned strings will require some new functionality.  There is no need for number-to-string conversion, but the detection of unknown strings is still needed.

IEEE OUIs could be handled as assigned numbers, if the compiler will accept enumerations with nearly 64,000 entries.  This has not been tried yet.  It will probably work, but if not, another approach will be needed.

The Makefile would be considerably shorter if the CSV file names could be computed from the list of file and class names, but it is not clear that make supports the syntax for that.
