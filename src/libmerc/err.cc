// err.cc
//
// flexible error reporting, using a printf-style interface and
// syslog-style severity levels

#include <stdarg.h>
#include <stdio.h>
#include "err.h"

int printf_err_func(log_level level, const char *format, ...) {

    // output error level message
    //
    const char *msg = "";
    switch(level) {
    case log_emerg:   msg = "emergency: ";     break;
    case log_alert:   msg = "alert: ";         break;
    case log_crit:    msg = "critical: ";      break;
    case log_err:     msg = "error: ";         break;
    case log_warning: msg = "warning: ";       break;
    case log_notice:  msg = "notice: ";        break;
    case log_info:    msg = "informational: "; break;
    case log_debug:   msg = "debug: ";         break;
    case log_none:  break;  // leave msg empty
    }
    int retval = fprintf(stderr, "%s", msg);

    // output formatted argument list
    //
    va_list args;
    va_start(args, format);
    retval += vfprintf(stderr, format, args);
    va_end(args);

    return retval;
}

int silent_err_func(log_level, const char *, ...) {
    return 0;
}

printf_err_ptr printf_err = printf_err_func;

void register_printf_err_callback(printf_err_ptr callback) {

    if (callback == nullptr) {
        printf_err = silent_err_func;
    } else {
        printf_err = callback;
    }
}
