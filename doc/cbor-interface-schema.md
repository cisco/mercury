# CBOR Metadata Interface Schema

This note documents the data format used in the Mercury CBOR metadata interface. The interface encodes per-packet feature metadata (exposed credentials, cryptographic assessment) into a compact CBOR buffer that is passed from libmerc to the mercury inspector via the `mercury_packet_processor_get_cbor_metadata()` C API. The inspector decodes the buffer and injects the metadata into the enrichment string for Connection Events and Splunk.

The format is encoded using [CBOR](https://datatracker.ietf.org/doc/html/rfc8949) (Concise Binary Object Representation). All maps use indefinite-length encoding (major type 5, additional info 31). All text strings use definite-length encoding (major type 3).

## Outer Buffer Format

The outer buffer is an indefinite-length CBOR map containing exactly one
key-value pair: a version key (currently `"v1"`) whose value is an inner
indefinite-length map of feature entries. Each inner key-value pair is a
feature entry, keyed by attribute tag name.

```
cbor_metadata_buffer = {
    "v1": {
        * feature_key => feature_value   ; zero or more feature entries
    }
}
```

There is **no** `schema_version` integer in the buffer. The version is carried
by the outer map key string. The constant is `CBOR_METADATA_VERSION_KEY`
(value `"v1"`) in `cbor_messages.hpp` — not `CBOR_METADATA_SCHEMA_VERSION`.

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

```
"cnsa_2_0_non_conformant": {
    "policy": "quantum_safe",
    <target>: {                        ; "client", "session", or "offered"
        ? "ciphersuites_not_allowed": [* tstr],   ; cipher suite names or hex codes
        ? "ciphersuites_allowed": tstr,            ; "all", "some", or "none"
        ? "groups_not_allowed": [* tstr],          ; named group names or hex codes
        ? "groups_allowed": tstr,                  ; "all", "some", or "none"
        "tls_cert_with_extern_psk": bool,
        ? <non_compliant_key>: tstr                ; reason string if PSK non-compliant
    }
}
```

Where `<target>` is one of `"client"` (TLS client hello), `"session"` (TLS server hello), or `"offered"` (SSH kex init).

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

To add a new feature to the CBOR metadata interface:

1. **Add a feature class** in `src/libmerc/cbor_messages.hpp` following the `exposed_creds_message` pattern: `cbor::text_string` members, `construct()` / `decode()` static methods, templated `write<Object, Array>()`.

2. **Add a typed bucket** in `struct cbor_decoded_metadata` (`src/libmerc/cbor_decoded_metadata.hpp`) if the inspector needs typed access to the feature, and add KEY dispatch in `decode_v1()`. The decoder uses typed bucket members (plus a `std::vector<unknown_feature>` for unrecognized keys) — **not** a `std::variant`. Single-fire features are plain members checked via `is_valid()`; features that can fire multiple times per packet use a vector.

3. **Wire the encode path** in `src/libmerc/pkt_proc.cc`: add a visitor overload that constructs and writes the feature class. Call `cbor_meta_->set_feature_written()` only at the actual CBOR write site.

4. **Add unit tests**: round-trip test in `cbor_decoded_metadata_test.hpp`, plus an unknown-field test, and a protocol accessor test in the protocol's `unit_test()`.

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
