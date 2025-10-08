// csv.h
//
// a C++ header-only library implementing a reader for Comma Separated
// Value (CSV) formatted data, using a finite state machine
// based lexer
//
// Copyright (c) 2022 David McGrew
//
// The CSV format is as defined in tools.ietf.org/html/rfc4180, except
// that lines can be terminated with either CR LF (as per the RFC) or
// just LF (as might happen on some operating systems).

#ifndef CSV_H
#define CSV_H

#include <cstdio>
#include <vector>
#include <string>

class csv {

public:

    enum state  {
        S,   // start of record
        UQ,  // unquoted field
        Q,   // quoted field
        AQ,  // after quote, in quoted field
        AF,  // after field end
        CR,  // carriage return
        ERR  // error
    };

    enum symbol { quote, cr, lf, comma, other };

    static enum symbol get_symbol(char c) {
        switch(c) {
        case ',':  return comma;
        case '"':  return quote;
        case '\r': return cr;
        case '\n': return lf;
        default:
            ;
        }
        return other;
    }

    static enum state next_state(enum state current_state, enum symbol symbl) {
        switch (current_state) {
        case Q:
            switch (symbl) {
            case quote:   return AQ;
            case other:   return Q;
            case cr:      return Q;
            case lf:      return Q;
            case comma:   return Q;
            }
            break;
        case AQ:
            switch (symbl) {
            case quote:   return Q;
            case other:   return ERR;
            case cr:      return CR;
            case lf:      return S;
            case comma:   return AF;
            }
            break;
        case UQ:
            switch (symbl) {
            case quote:   return ERR;
            case other:   return UQ;
            case cr:      return CR;
            case lf:      return S;
            case comma:   return AF;
            }
            break;
        case AF:
            switch (symbl) {
            case quote:   return Q;
            case other:   return UQ;
            case cr:      return CR;
            case lf:      return S;
            case comma:   return AF;
            }
            break;
        case S:
            switch (symbl) {
            case quote:   return Q;
            case other:   return UQ;
            case cr:      return CR;
            case lf:      return S;
            case comma:   return AF;
            }
            break;
        case CR:
            switch (symbl) {
            case quote:   return Q;
            case other:   return UQ;
            case cr:      return CR;
            case lf:      return S;
            case comma:   return AF;
            }
            break;
        default:
            ;
        }
        return ERR;
    }

    static char *state_name(enum state s) {
        switch (s) {
        case Q:   return (char *)"Q";
        case AQ:  return (char *)"AQ";
        case UQ:  return (char *)"UQ";
        case CR:  return (char *)"CR";
        case S:   return (char *)"S";
        case AF:  return (char *)"AF";
        case ERR: return (char *)"ERR";
        default:
            ;
        }
        return (char *)"unknown";
    }

    static std::vector<std::string> get_next_line(std::istream &in) {
        std::vector<std::string> line;
        std::string field;
        csv::state state = csv::state::S;
        while (true) {
            char c;
            in.get(c);
            if (!in.good()) {
                break;
            }
            // fprintf(stdout, "state: %s\tchar: %c\n", state_name(state), c);
            state = csv::next_state(state, get_symbol(c));
            if (state == csv::UQ || (state == csv::Q && c != '"')) {
                field.push_back(c);
            }
            if (state == csv::AF) {
                line.push_back(field);
                field.clear();
            }
            if (state == csv::S) {
                line.push_back(field);
                field.clear();
                break;
            }
            // note: we intentionally ignore csv::CR
        }

        return line;
    }
};

// class csv_processor defines a CSV-file processor, which accepts a
// sequence of lines (each of which is a vector of strings) of equal
// lengths
//
class csv_processor {
    bool first = true;
public:
    csv_processor() { };
    virtual void preamble() { first = true; }
    virtual void postamble() { }
    virtual bool process_line(const std::vector<std::string> &fields) = 0;
};

// class csv_printer merely prints out the fields of each CSV line
//
class csv_printer : public csv_processor {
    FILE *f;

public:
    csv_printer(FILE *file) : f{file} {}

    virtual bool process_line(const std::vector<std::string> &fields) {
        if (fields.size() == 0) {
            return true;
        }
        for (auto & x : fields) {
            fprintf(f, "'%s'\t", x.c_str());
        }
        fprintf(f, "\n");
        return true;
    }
};

// class csv_to_json converts a CSV file into JSON, using the first
// CSV line as the keys, and the following lines as values
//
class csv_to_json : public csv_processor {
    FILE *f;
    bool first_line = true;
    std::vector<std::string> keys;

public:
    csv_to_json(FILE *file) : f{file} {}

    // read in the fields of the first line, for use as the keys of a JSON object
    //
    bool process_first_line(const std::vector<std::string> &fields) {
        for (const auto & f : fields) {
            keys.push_back(f);
        }
        return true;
    }

    virtual bool process_line(const std::vector<std::string> &fields) { // TODO: pass by reference
        if (first_line) {
            first_line = false;
            return process_first_line(fields);
        }
        if (fields.size() != keys.size()) {
            fprintf(stderr, "error: inconsistent number of columns (expected %zu, got %zu)\n", keys.size(), fields.size());
            return false;
        }
        fputc('{', f);
        bool comma = false;
        for (size_t i=0; i<keys.size(); i++) {
            if (comma) {
                fputc(',', f);
            }
            comma = true;
            write_json_string(f, keys[i].c_str(), keys[i].size());
            fputc(':', f);
            write_json_string(f, fields[i].c_str(), fields[i].size());
        }
        fputc('}', f);
        fputc('\n', f);
        return true;
    }

    // write_json_string(f, data, len) writes the string data of
    // length len to the FILE *f, adding escape characters as needed
    // so that the string is JSON-legal
    //
    void write_json_string(FILE *f, const char *data, unsigned int len) {
        static char hex_table[] = {
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
        };
        fputc('"', f);
        for (unsigned int i = 0; i < len; i++) {
            if ((data[i] < 0x20) || // escape control characters
                (data[i] > 0x7f)) { // escape non-ASCII characters
                fputs("\\u00", f);
                fputc(hex_table[(data[i] & 0xf0) >> 4], f);
                fputc(hex_table[data[i] & 0x0f], f);
            } else {
                if (data[i] == '"' || data[i] == '\\') { // escape special characters
                    fputc('\\', f);
                }
                fputc(data[i], f);
            }
        }
        fputc('"', f);
    }

};


#endif // CSV_H
