// err.h
//
// flexible error reporting, using a printf-style interface and
// syslog-style severity levels

#ifndef ERR_H
#define ERR_H

#include <stdarg.h>

// enum log_level indicates the importance of a message passed to
// the error-printing callback function.  The levels are modeled after
// those of the SYSLOG facility.
//
enum log_level {
    log_emerg   = 0,  // system is unusable
    log_alert   = 1,  // action must be taken immediately
    log_crit    = 2,  // critical conditions
    log_err     = 3,  // error conditions
    log_warning = 4,  // warning conditions
    log_notice  = 5,  // normal but significant condition
    log_info    = 6,  // informational
    log_debug   = 7,  // debug-level messages
    log_none    = 8   // not a log message
};

// printf_err_ptr is a typedef of a function pointer for a
// printf-style function that handles error output.  It can be used to
// implement a register an error-handling function that performs
// specialized output of a formatted error message.
//
typedef int (*printf_err_ptr)(log_level level, const char *format, ...);

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
