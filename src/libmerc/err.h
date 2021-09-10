// err.h
//
// flexible error reporting, using a printf-style interface

#ifndef ERR_H
#define ERR_H

#include <stdarg.h>

// printf_err_ptr is a typedef of a function pointer for a
// printf-style function that handles error output.  It can be used to
// implement a register an error-handling function that performs
// specialized output of a formatted error message.
//
typedef int (*printf_err_ptr)(const char *format, ...);

// register_printf_err_callback() registers a callback function for
// printing error messages with a printf-style function.  The function
// int printf_err_func() in err.cc provides an example of how to
// construct such a function using a standard C va_list.
//
// If the callback argument passed to this function is null, then no
// error messages will be output.  (That is, the callback is set to a
// function that ignores its arguments and generates no output.)


void register_printf_err_callback(printf_err_ptr callback);

#endif // ERR_H
