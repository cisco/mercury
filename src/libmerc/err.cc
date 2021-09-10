// err.cc
//
// flexible error reporting, using a printf-style interface

#include <stdarg.h>
#include <stdio.h>
#include "err.h"

int printf_err_func(const char *format, ...) {
    va_list args;
    va_start(args, format);
    int retval = vfprintf(stderr, format, args);
    va_end(args);
    return retval;
}

int silent_err_func(const char *, ...) {
    return 0;
}

//printf_err_ptr printf_err = silent_err_func;

printf_err_ptr printf_err = printf_err_func;

void register_printf_err_callback(printf_err_ptr callback) {

    if (callback == nullptr) {
        printf_err = silent_err_func;
    } else {
        printf_err = callback;
    }
}
