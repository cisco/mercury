// protocol.h
//

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "datum.h"
#include "fingerprint.h"

class classifier; // forward declaration of class used in interface

// the base_protocol class declares the interface for protocols that
// work with the mercury packet processing code.  To implement a class
// that represents a protocol message, define a class that derives
// from this one and redefines the appropriate member functions to
// provide the behavior for the protocol message.  The
// compute_fingerprint() and do_analysis() functions need not be
// supported by every protocol, but most protocols will want to
// provide the write_json() functionality.
//
class base_protocol {

public:

    bool is_not_empty() const { return false; }

    void write_json(struct json_object &) { }

    void compute_fingerprint(fingerprint &) const { }

    bool do_analysis(const struct key &, struct analysis_context &, classifier*) { return false; }

};

#endif // PROTOCOL_H
