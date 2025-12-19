// \file diagnostic.hpp
//

#ifndef DIAGNOSTIC_HPP
#define DIAGNOSTIC_HPP

#include "datum.h"

/// \brief Read a `datum` and print its contents without changing it.
///
/// This class can be used to debug a constructor that parses an input
/// `datum`, by peeking into the state of the input at any point in
/// the member initializer list.  When an object of class `diagnostic`
/// is included in the member initializer list, it will print out the
/// contents of the `datum` after it has been processed by the
/// previous members in the initializer list.  It does not alter the
/// input, so the inialization of the successive members is
/// unaffected.
///
class diagnostic {
public:

    /// \brief Speficies an output type.
    ///
    enum output {
        hex,      ///< Hexadecimal output.
        ascii     ///< ASCII output, with a `.` replacing each non-printable character.
    };

    /// \brief Read `datum` \p input and print its contents without
    /// changing it.
    ///
    /// By default, the contents of \p input are printed out as a
    /// hexadeicmal byte sequence, with no preamble, to `stderr`,
    /// unless `input` is in the null state, in which case `(null)` is
    /// printed, or the input is in the empty state, in which case
    /// `(empty)` is printed.  The optional argument \p output_type
    /// can be set to `diagnostic::output::ascii`, which prints out a
    /// readable `datum` as ASCII text with `.` replacing
    /// non-printable characters, or set to `diagnostic::output::hex`
    /// to obtain the default behavior.  When the optional argument \p
    /// preamble is set to a null-terminated character string, that
    /// string is printed out before the contents of `input`.  When
    /// the optional argument \p output_file is set, all output is
    /// written to that `FILE *` instead of `stderr`.
    ///
    diagnostic(const datum &input,                 ///< the data input
               output output_type=hex,             ///< the output type (optional; default=`output::hex`)
               const char *preamble=nullptr,       ///< the text preamble (optional)
               FILE *output_file=stderr)           ///< the `FILE *` for output (optional; default=`stderr`)
    {
        if (preamble) {
            fprintf(output_file, "%s: ", preamble);
        }
        if (input.is_null()) {
            fprintf(output_file, "(null)\n");
        }
        if (input.is_empty()) {
            fprintf(output_file, "(empty)\n");
        }
        switch(output_type) {
        case ascii:   input.fprint(output_file);     break;
        case hex:     input.fprint_hex(output_file); break;
        default:      ;
        }
        fputc('\n', output_file);
    }
};

#endif // DIAGNOSTIC_HPP
