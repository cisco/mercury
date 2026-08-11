# CBOR Metadata Interface Schema

This note documents the data format used in the Mercury CBOR metadata interface. The interface encodes feature metadata (exposed credentials, cryptographic assessment) into a compact CBOR buffer that is passed via the `mercury_packet_processor_get_cbor_metadata()` C API.

The format is encoded using [CBOR](https://datatracker.ietf.org/doc/html/rfc8949) (Concise Binary Object Representation).

## Outer Buffer Format

The outer buffer is an indefinite-length CBOR map containing a version key (currently `"v1"`) whose value is an inner indefinite-length map of feature entries. Each inner key-value pair is a feature entry, keyed by feature key name.

```
cbor_metadata_buffer = {
    "v1": {
        * feature_key => feature_value   ; zero or more feature entries
    }
}
```

If no features fire for a packet, the buffer is empty (length 0) and
`get_cbor_metadata()` returns `CBOR_NO_DATA`.

## Schema Version

The outer version key enables forward compatibility. `decode_cbor_metadata()`
checks the key:
- If the outer version key is the recognized version (`"v1"`): the inner map is
  decoded via the version-dispatched function `decode_v1()`, and the result is
  marked `valid == true` on clean decode.
- If the outer version key is unrecognized (e.g. `"v99"`): the value is skipped
  and the decode result is marked `valid == false`. An old decoder MUST NOT
  treat a future schema as valid empty metadata.

Version bump policy:
- New field added to existing message: no version bump (unknown inner keys are skipped).
- New message type added: no version bump (unknown inner keys become `unknown_feature`).
- Breaking change (field renamed, restructured, or removed): bump the version key
  (e.g. `"v1"` → `"v2"`) and add a `decode_v2()` dispatch.

## Message Types

### `exposed_credentials_plaintext`

Fired when plaintext password exposure is detected (e.g., HTTP Basic, IMAP LOGIN, FTP PASS).

```
"exposed_credentials_plaintext": {
    "protocol": tstr,                  ; MANDATORY — "imap", "http", "tacacs", "ldap", "ftp", "snmp", "redis"
    "authentication_method": tstr,     ; MANDATORY — "LOGIN", "Basic", "PASS", "AUTH", "simple", "community", etc.
    ? "username": tstr                 ; optional — absent for protocols that don't expose it
}
```

### `exposed_credentials_token`

Fired when plaintext token exposure is detected (e.g., HTTP Bearer, IMAP OAUTHBEARER).

```
"exposed_credentials_token": {
    "protocol": tstr,                  ; MANDATORY
    "authentication_method": tstr      ; MANDATORY — "Bearer", "OAUTHBEARER", "XOAUTH2", "GSSAPI"
}
```

### `exposed_credentials_derived`

Fired when password-derived credential exposure is detected (e.g., challenge-response mechanisms).

```
"exposed_credentials_derived": {
    "protocol": tstr,                  ; MANDATORY
    "authentication_method": tstr      ; MANDATORY — "CRAM-MD5", "DIGEST-MD5", "SCRAM-SHA-256", "NTLM", "encrypted"
}
```

### `cnsa_2_0_non_conformant`

Fired when CNSA 2.0 (quantum-safe) cryptographic policy non-conformance is detected.

The metadata under this one key has TWO shapes, selected by the protocol being
assessed. Both are emitted under the same key `cnsa_2_0_non_conformant`; a decoder
tells them apart by reading the `cnsa_variant` discriminator field (`"tls"` or
`"ssh"`) — see the note on shared-key routing below.

TLS (`<target>` is `"client"` for the client hello, `"session"` for the server hello):

```
"cnsa_2_0_non_conformant": {
    "policy": "quantum_safe",
    "cnsa_variant": "tls",                         ; discriminator
    <target>: {                                    ; "client" or "session"
        ? "ciphersuites_not_allowed": [* tstr],    ; cipher suite names or hex codes
        ? "ciphersuites_allowed": tstr,            ; "all", "some", or "none"
        ? "groups_not_allowed": [* tstr],          ; named group names or hex codes
        ? "groups_allowed": tstr,                  ; "all", "some", or "none"
        "tls_cert_with_extern_psk": bool,          ; always present (TLS only)
        ? <non_compliant_key>: tstr                ; reason string if PSK non-compliant
    }
}
```

SSH (`<target>` is always `"offered"`):

```
"cnsa_2_0_non_conformant": {
    "policy": "quantum_safe",
    "cnsa_variant": "ssh",                         ; discriminator
    "offered": {
        ? "kex_not_allowed": [* tstr],             ; key-exchange algorithm names
        ? "kex_allowed": tstr,                     ; "all", "some", or "none"
        "client_to_server": {
            ? "ciphersuites_not_allowed": [* tstr],
            ? "ciphersuites_allowed": tstr         ; "all", "some", or "none"
        },
        "server_to_client": {
            ? "ciphersuites_not_allowed": [* tstr],
            ? "ciphersuites_allowed": tstr         ; "all", "some", or "none"
        }
    }
}
```

The SSH shape does NOT emit `tls_cert_with_extern_psk`, `groups_*`, or the
top-level `ciphersuites_*` fields; those are TLS-only. Conversely the TLS shape
does not emit `kex_*` or the `client_to_server`/`server_to_client` sub-maps.

### `nist_sp_800_52_2_non_conformant`

Fired when NIST SP 800-52 Rev 2 cryptographic policy non-conformance is detected.

```
"nist_sp_800_52_2_non_conformant": {
    "policy": "nist_sp_800_52_2",
    ? "negotiated_parameters": {       ; present when verbose output enabled
        ? "protocol_version": tstr,    ; "TLSv1.0", "TLSv1.2", "TLSv1.3", etc.
        "extensions": [* tstr],        ; extension names (may be empty array)
        ? "cipher_suite": tstr,        ; negotiated cipher suite name
        ? "supported_group": tstr      ; negotiated supported group name
    },
    "compliance_result": {
        ? <non_compliant_key>: tstr,   ; at most one non-compliant reason
        "compliant": bool
    }
}
```

Non-compliant keys include: `tls_version_non_compliant`, `cipher_suite_non_compliant`, `supported_groups_missing`, `ec_points_format_non_compliant`, `supported_group_non_compliant`, `encrypt_then_mac_non_compliant`, `compression_method_non_compliant`.

## Truncation Status

The inner (`"v1"`) map may carry a top-level `"truncation"` key describing whether the
assessed packet/handshake was fully present. It is a **status field, not a feature**: it is
a sibling of the feature keys, and it is emitted whenever the buffer carries at least one
feature (a buffer that would contain only `truncation` and no feature is dropped as
`CBOR_NO_DATA`). It is a **reserved key** — the decoder captures it into its own field
(`typed_decoder::truncation`), never as a feature slot or an `unknown_feature` — so consumers
read the packet status separately from the list of detected features.

```
"truncation": tstr        ; "none" | "reassembled" | "truncated" | "reassembled_truncated"
```

| Value | Meaning |
|-------|---------|
| `none` | Packet arrived complete; no reassembly needed. |
| `reassembled` | Handshake was reassembled from multiple segments and is complete. |
| `truncated` | Handshake payload was cut short (incomplete). |
| `reassembled_truncated` | Reassembled but still incomplete. |

This describes **Type A** truncation (the packet/handshake itself). It is distinct from
**Type B** truncation — the CBOR metadata buffer running out of space mid-encode — which
cannot be reported inside the buffer (the buffer is what overflowed) and is instead signaled
by the C-API return code `CBOR_WRITE_INSUFFICIENT_SPACE` (see `enum cbor_metadata_return` in
`libmerc.h`). Note: the FDC output reports the same Type A status as an **integer**; the CBOR
buffer uses the **string** form deliberately, so the buffer is self-describing without the
C++ enum. Same status, two encodings, separate outputs.

## Controlled Vocabularies

### Protocol Names

| Value | Protocol |
|-------|----------|
| `imap` | IMAP (RFC 3501) |
| `http` | HTTP/1.1 |
| `tacacs` | TACACS+ |
| `ldap` | LDAP (RFC 4511) |
| `ftp` | FTP (RFC 959) |
| `snmp` | SNMP v2c/v3 |
| `redis` | Redis |

### Authentication Methods

| Value | Context |
|-------|---------|
| `LOGIN` | IMAP LOGIN command |
| `PLAIN` | SASL PLAIN mechanism |
| `CRAM-MD5` | SASL CRAM-MD5 |
| `DIGEST-MD5` | SASL DIGEST-MD5 |
| `SCRAM-SHA-1` | SASL SCRAM-SHA-1 |
| `SCRAM-SHA-256` | SASL SCRAM-SHA-256 |
| `OAUTHBEARER` | SASL OAUTHBEARER |
| `XOAUTH2` | SASL XOAUTH2 |
| `GSSAPI` | SASL GSSAPI |
| `NTLM` | SASL NTLM |
| `Basic` | HTTP Basic Authentication |
| `Bearer` | HTTP Bearer Token |
| `Digest` | HTTP Digest Authentication |
| `ASCII` | TACACS+ ASCII auth type |
| `encrypted` | TACACS+ encrypted body |
| `PASS` | FTP PASS command |
| `AUTH` | Redis AUTH command |
| `simple` | LDAP simple bind |
| `community` | SNMP v2c community string |
| `auth` | SNMP v3 authentication |

### Crypto Assessment Policies

| Value | Standard |
|-------|----------|
| `quantum_safe` | CNSA 2.0 post-quantum readiness |
| `nist_sp_800_52_2` | NIST SP 800-52 Rev 2 TLS compliance |

## Extension Process

### How decoding works

Each feature is implemented as a **feature class** (in `cbor_messages.hpp`) that knows how
to recognize its own key(s) and decode its own CBOR sub-map — the exact members are the
**feature contract** listed in step 1 below.

The decoder, `cbor_decoded_metadata`, is a **registry** of feature classes. "Registering"
a feature simply means listing its class in that registry's type list
(`typed_decoder<Features...>` in `cbor_decoded_metadata.hpp`); the registry keeps one typed
slot per listed class. To decode a buffer it walks each inner key and offers it to every
registered class's `matches()` in turn — the first that accepts decodes into its slot,
giving the caller typed field access. A key no registered class accepts is kept as an
`unknown_feature` (its key + raw CBOR span), so **registration is optional**: an
unregistered or future feature is never lost — it just lands in the `unknown` list instead
of a typed slot. Either way a consumer can read convert it into valid JSON, by `key()` + `cbor_span()`.

A feature's key(s) and its class has a **many-to-many** relationship:

- **One class, several keys** — a single registered class recognizes a key-group in its
  `matches()` (e.g. `exposed_creds_message` matches
  `exposed_credentials_plaintext`/`_token`/`_derived`) and uses the matched key in
  `decode_into()` to decode the right shape.
- **One key, several schemas** — give each schema its own feature class (one per shape),
  then add a separate **wrapper feature class** that holds a discriminated (tagged) union
  (`std::variant`) of those schema classes. Register only the wrapper — so exactly one
  registered class recognizes that key and the choice between schemas happens inside 
  the wrapper class rather than during key routing. Example: the
  schema classes `crypto_cnsa_tls_message` and `crypto_cnsa_ssh_message` each decode one
  shape; the wrapper `cnsa_feature` holds
  `std::variant<std::monostate, crypto_cnsa_tls_message, crypto_cnsa_ssh_message>`, and its
  `decode_into()` reads the `cnsa_variant` discriminator, constructs the matching
  alternative, and exposes typed access via `tls_if()`/`ssh_if()`.

In both cases `matches()` decides recognition and `decode_into()` selects the shape.

To add a new feature:

1. **Add a non-owning feature class** in `cbor_messages.hpp` satisfying the feature
   contract:
   - `static <Msg> decode(datum &d[, const char *key])` — the factory that parses the
     CBOR sub-map into a decoded instance; the workhorse each `decode_into()` delegates to;
   - `static bool matches(datum key)` — recognize the feature's key (or key-group);
   - `void decode_into(datum key, datum &d)` — route in place, then decode. For a
     multi-key class, use the matched key to decode the right shape. For one key that
     carries several schemas, write one feature class per schema and a separate wrapper
     class holding a `std::variant` of them; register the wrapper, and have its
     `decode_into()` read the discriminator and construct the matching alternative
     (see `cnsa_feature`);
   - `bool is_valid()`, `datum key()`, `datum cbor_span()` — validity, downstream key,
     and the raw CBOR span a consumer reads the feature by;
   - a templated `write<Object>(parent)` for serialization and a producer-side way to
     populate it. A feature that can fire multiple times per packet must hold its
     repeats internally; its `KEY` still appears once in the buffer.

2. **Register it only if a consumer needs typed field access** — add the class to the
   `typed_decoder<...>` type list in `cbor_decoded_metadata.hpp`. Otherwise skip this
   step; the feature is still read fine through the `unknown` list.

3. **Wire the encode path** in `src/libmerc/pkt_proc.cc`: add a visitor overload that
   constructs, populates, and writes the feature class.

4. **Add unit tests** in `cbor_decoded_metadata_test.hpp`: a round-trip test, an
   unknown-field (forward-compat) test, and a protocol accessor test in the protocol's
   `unit_test()`.

5. **Document** the new message type in this file.

No version-key bump is required for new fields or new message types. Unknown inner keys are skipped (or preserved as `unknown_feature`) by existing decoders via `skip_cbor_value()` (forward compatibility). Only a breaking restructure requires bumping the outer version key.

## Implementation Reference

| Component | File |
|-----------|------|
| Feature classes | `src/libmerc/cbor_messages.hpp` |
| Decode container | `src/libmerc/cbor_decoded_metadata.hpp` |
| CBOR buffer manager | `src/libmerc/cbor_metadata.hpp` |
| C API | `src/libmerc/libmerc.h`, `src/libmerc/libmerc.cc` |
| Encode wiring | `src/libmerc/pkt_proc.cc` |
| Version key constant | `CBOR_METADATA_VERSION_KEY` (`"v1"`) in `cbor_messages.hpp` |
| Unit tests | `src/unit_test.cpp`, `src/libmerc/cbor_decoded_metadata_test.hpp` |
