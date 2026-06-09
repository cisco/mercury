// printf_err.h -- libmerc logging helper.
//
// Header-only printf_err() used throughout libmerc.  Routes messages
// through the callback installed by register_printf_err_callback()
// (see libmerc.h); defaults to stderr with a severity prefix.

#ifndef LIBMERC_PRINTF_ERR_H
#define LIBMERC_PRINTF_ERR_H

#include "libmerc.h"  // for enum log_level, printf_err_ptr

#include <cstdarg>
#include <cstdio>

inline int printf_err_func(enum log_level level, const char *format, va_list args) {
    const char *msg = "";
    switch (level) {
    case log_emerg:   msg = "emergency: ";     break;
    case log_alert:   msg = "alert: ";         break;
    case log_crit:    msg = "critical: ";      break;
    case log_err:     msg = "error: ";         break;
    case log_warning: msg = "warning: ";       break;
    case log_notice:  msg = "notice: ";        break;
    case log_info:    msg = "informational: "; break;
    case log_debug:   msg = "debug: ";         break;
    case log_none:    break;
    }
    int retval = std::fprintf(stderr, "%s", msg);
    if (retval < 0) {
        return retval;
    }
    int sum = retval;
    retval = std::vfprintf(stderr, format, args);
    if (retval < 0) {
        return retval;
    }
    return sum + retval;
}

inline int silent_err_func(enum log_level, const char *, va_list) {
    return 0;
}

// Active callback; mutated by register_printf_err_callback().  C++17
// inline variable gives one linker-merged instance per binary.
//
inline printf_err_ptr printf_err_callback = printf_err_func;

inline int printf_err(enum log_level level, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int retval = printf_err_callback(level, format, args);
    va_end(args);
    return retval;
}

#endif // LIBMERC_PRINTF_ERR_H
