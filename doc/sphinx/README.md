# Sphinx/Breathe/Doxygen Documentation

These instructions explain how to use the inline comments in some
mercury files to automatically create documentation.  This
auto-documentation facility uses the Sphinx, Breathe, and Doxygen
packages, with the `Read The Docs' (rtd) format.

## Prerequisites

The prerequisites are:

* sphinx

* breathe

* doxygen

* make

On a recent version of Ubuntu, these commands should install those prerequisites:
```
$ sudo apt install python3-sphinx
$ sudo apt install doxygen
$ sudo apt install make
$ pip install breathe
$ pip install sphinx-rtd-theme
```

## Building

In the current directory (which should contain the `source` and `build` subdirectories), run
```
$ make html
```

This will build the HTML documentation, which will appear in the
`./build/html` subdirectory.  The file `./build/html/index.html` is a
good starting point.



