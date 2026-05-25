# Code Review: `dev...interface_cbor2` — Issues & Resolutions

## Issue 1: Stale CBOR buffer on early-exit paths (Medium) — RESOLVED

**Problem:** `cbor_meta.reset()` was placed at line 1842 in `pkt_proc.cc`, inside the `if (is_not_empty)` block after `compute_fingerprint`. If `analyze_ip_packet()` exited early (invalid TCP header, reassembly in-progress, monostate protocol), the buffer retained data from the previous packet. The inspector calls `get_cbor_metadata()` regardless of `analysis_ctxt` being null (confirmed at `mercury_inspector.cc:608`), so it could read stale data.

**Fix:** Moved `cbor_meta.reset()` to line 1764, immediately after `analysis.reinit()`. This ensures every call to `analyze_ip_packet()` clears the CBOR buffer upfront, matching the contract of `analysis.reinit()`. The encoding logic at line 1843+ still works because `get_writer()` returns the already-reset writeable.

**Verification:** All 41 unit tests pass, build clean.

---

## Issue 2: JSON injection risk in datum-accepting methods (Low-Medium) — RESOLVED

**Problem:** The new `print_key_string(const char*, datum)`, `print_key_string(datum, datum)`, `json_object(json_object&, datum)`, and `json_array::print_string(datum)` methods used raw `memcpy` without JSON escaping. While the fields they carry (protocol names, auth methods) are safe ASCII from parsers, this was a missing defense-in-depth layer.

**Analysis:** The feature class templates (`cbor_messages.hpp`) originally called `print_key_json_string` for some fields and `print_key_string` for others, creating inconsistency and requiring shim methods on both types.

**Fix (multi-part):**

1. **Unified template interface:** Changed all template calls in `cbor_messages.hpp` to use `print_key_string` exclusively (removed `print_key_json_string` calls).

2. **Added JSON escaping to datum methods in `json_object.h`:**
   - `print_key_string(const char*, datum)` → delegates to `print_key_json_string` (uses `utf8_string`)
   - `print_key_string(datum, datum)` → escapes both key and value via `utf8_string::write()`
   - `json_object(json_object&, datum)` constructor → escapes the key via `utf8_string::write()`
   - `json_array::print_string(datum)` → escapes value via `utf8_string::write()`

3. **Removed dead shim:** Deleted `cbor_object::print_key_json_string` — it was only needed when templates called both names.

**Result:** Templates call `print_key_string`; `json_object` escapes properly, `cbor_object` writes raw UTF-8 (correct for CBOR). Clean separation, no shims.

**Verification:** All 41 unit tests pass, crypto assessment JSON output unchanged.

---

## Issue 3: `crypto_cnsa_message::decode()` fragile catch-all in target map (Low) — RESOLVED

**Problem (two sub-issues):**

1. **Forward compatibility:** In the target sub-map decoding loop, any unknown key was unconditionally treated as a PSK non-compliant entry. If a future encoder adds new fields (e.g., `"signature_algorithms_not_allowed"`), a v1 decoder would misinterpret them as PSK compliance failures — or worse, if the new field's value is an array/map, `cbor::text_string::decode(d)` would fail and corrupt the parse.

2. **Data loss:** The encoder writes up to 4 PSK non-compliant entries (sequential `if` checks, not `else if`), but the class only stored one — `set_psk_non_compliant()` overwrote on each call. Only the last PSK entry survived encoding.

**Fix (multi-part):**

1. **Storage:** Changed single `psk_non_compliant_key_`/`reason_` to fixed arrays of size `MAX_PSK_ENTRIES = 4`:
   ```cpp
   cbor::text_string psk_non_compliant_keys_[MAX_PSK_ENTRIES];
   cbor::text_string psk_non_compliant_reasons_[MAX_PSK_ENTRIES];
   size_t            psk_non_compliant_count_ = 0;
   ```

2. **Setter:** `set_psk_non_compliant()` now appends instead of overwriting.

3. **Write:** Iterates all PSK entries:
   ```cpp
   for (size_t i = 0; i < psk_non_compliant_count_; i++) {
       tgt.print_key_string(psk_non_compliant_keys_[i].value(),
                             psk_non_compliant_reasons_[i].value());
   }
   ```

4. **Decode:** Explicitly matches the 4 known PSK keys. Unknown keys get `skip_cbor_value(d)`:
   ```cpp
   else if (tk.match("tls_cert_with_extern_psk_non_compliant") ||
            tk.match("psk_key_exchange_modes_non_compliant") ||
            tk.match("psk_key_exchange_mlkem1024_non_compliant") ||
            tk.match("pre_shared_key_non_compliant")) {
       // append to array
   }
   else {
       cbor::skip_cbor_value(d);  // unknown field — safe skip
   }
   ```

5. **Accessors:** Replaced `psk_non_compliant_key_valid()`/`value()` with `psk_non_compliant_count()`/`psk_non_compliant_key_at(i)`/`psk_non_compliant_reason_at(i)`.

6. **Updated caller** in `crypto_assess.h` unit test to iterate the array.

**Unit tests added:**
- Test 3a: Multi-PSK round-trip — encodes 2 PSK entries, verifies both decode correctly with correct keys.
- Test 3a2: Forward compatibility — manually encodes an unknown field (`"signature_algorithms_not_allowed"`) in the target sub-map, verifies it's skipped without corrupting the decode and `psk_non_compliant_count == 0`.

**Verification:** All 41 unit tests pass, crypto assessment JSON output unchanged.

---

## Issue 4: `CBOR_NO_DATA` never returned in current flow (Minor/Design) — RESOLVED

**Problem:** Since `schema_version` is always written to the buffer (even when no features fire), `cbor_meta.has_data()` is always `true` after `end_encode()`. The `CBOR_NO_DATA` return code in the C API was effectively dead code. The inspector always received a buffer, decoded it, found `count == 0`, and moved on — wasted decode overhead.

**Fix:** Added a `feature_written_` flag to `cbor_metadata_context` using the "speculative write with late discard" pattern:

1. **`cbor_metadata.hpp`:** Added `bool feature_written_` flag (cleared on `reset()`), `set_feature_written()` setter, and `end_encode()` returns `length_ = 0` if flag not set.

2. **`pkt_proc.cc`:** After each visitor returns, check whether a feature actually fired and call `cbor_meta.set_feature_written()`:
   - `exposed_creds_ret != exposed_creds_type::none` → set flag
   - `assessment_result.any()` → set flag
   - Applied in both branches (fingerprint-known and fingerprint-unknown)

3. Schema_version is still written eagerly (a few bytes to a stack buffer), but `end_encode()` discards the buffer if no feature set the flag. The C API then returns `CBOR_NO_DATA`, and the inspector skips decode entirely via its existing `if (cbor_ret > 0 && cbor_buf && cbor_len > 0)` check.

**Unit tests added:**
- Test 5b: No feature written → `has_data() == false`, `get_length() == 0`
- Test 5c: Feature written + flag set → `has_data() == true`, buffer decodable
- Test 5d: `reset()` clears the flag (next-packet simulation)

**Verification:** All 41 unit tests pass, crypto assessment JSON output unchanged.

---

## Issue 5: `cbor_array::print_uint16_hex` uses `snprintf` (Minor) — RESOLVED

**Problem:** Used `snprintf(buf, 5, "%04x", value)` for hex conversion — a general-purpose formatting function for a simple 4-nibble lookup. Not aligned with the codebase's existing `hex_table` pattern in `buffer_stream.h`.

**Fix:** Replaced with direct nibble extraction using the existing `hex_table`:
```cpp
void print_uint16_hex(uint16_t value) {
    char buf[4];
    buf[0] = hex_table[(value & 0xf000) >> 12];
    buf[1] = hex_table[(value & 0x0f00) >> 8];
    buf[2] = hex_table[(value & 0x00f0) >> 4];
    buf[3] = hex_table[value & 0x000f];
    datum d{(const uint8_t *)buf, (const uint8_t *)buf + 4};
    cbor::text_string::construct(d).write(a);
}
```

Same mask-then-shift style as `append_uint16_hex` in `buffer_stream.h`.

**Unit test added:** "Test 3 hex" — encodes `0xc02c`, `0x0005`, `0x001d` via `add_cs_not_allowed_hex`/`add_grp_not_allowed_hex`, decodes and verifies round-trip matches `"c02c"`, `"0005"`, `"001d"`.

**Verification:** All 41 unit tests pass.

---

## Issue 6: `crypto_cnsa_message` decode doesn't preserve hex/text distinction (Minor)

**Problem:** When encoding, ciphersuites can be added as either text (`add_cs_not_allowed("name")`) or hex (`add_cs_not_allowed_hex(0xC02C)`). The hex path writes the uint16 as a 4-char hex text string. On decode, all values come back as `text_string` — the `is_hex_` flags are never set during decode.

**Impact:** None for current usage. The inspector only reads the decoded values as text strings for JSON output. The hex/text distinction is an encode-side optimization (to avoid looking up cipher names when `readable_output` is false). Round-trip fidelity of the `is_hex_` flag is not needed.

**Status:** OPEN — by design, no action needed.

---

## Issue 7: CBOR crypto path wrote shared array instead of per-attribute KEYs (Medium) — RESOLVED

**Problem:** The `do_crypto_assessment` visitor's CBOR path wrote crypto features inside a `"cryptographic_security_assessment"` array (same as JSON path). But `decode_cbor_metadata()` dispatches by top-level KEY (`cnsa_2_0_non_conformant`, `nist_sp_800_52_2_non_conformant`). The decoder would treat the array as an `unknown_feature` and per-attribute metadata would be unavailable in the enrichment string.

**Fix:** Used `if constexpr (std::is_same_v<Object, json_object>)` to differentiate paths:
- JSON path: writes into `"cryptographic_security_assessment"` array (backward compat)
- CBOR path: writes each feature under its own KEY via `cbor::text_string(KEY).write(...)`, only when non-compliant

**Verification:** E2E verified — crypto metadata `{"policy":"quantum_safe","client":{"ciphersuites_not_allowed":[...],...}}` appears in Snort unified.out enrichment JSON. All 41 unit tests pass, JSON baseline unchanged.

---

## Issue 8: `skip_cbor_value()` fails on definite-length containers (Medium) — RESOLVED

**Problem:** `skip_cbor_value()` used `cbor::array{d}` / `cbor::map{d}` which only accept indefinite-length containers (additional_info == 31). Definite-length arrays/maps (e.g., `0x83` = 3-item array) would set datum to null, breaking forward-compatible decoding. Also used raw `*d.data != 0xff` instead of `is_break()`.

**Fix:** Rewrote array and map cases to read `initial_byte`, branch on `additional_info == 31` (indefinite → scan to break) vs definite (decode count, skip N items). Used `is_break()` for all break byte checks.

**Verification:** Unit tests added for definite-length array (`0x83`) and map (`0xa1`). All 41 tests pass.

---

## Issue 9: `decode_v1()` overflow leaves datum misaligned (Low-Medium) — RESOLVED

**Problem:** When `out.count` reaches `MAX_ENTRIES` (8), the while loop exits. If more entries remain in the CBOR map before the break byte, `m.close()` can't find `0xFF`, sets datum null, and `out.valid` becomes false — even though the first 8 entries were decoded correctly.

**Fix:** Added a drain loop after the main decode loop:
```cpp
while (d.is_not_empty() && !cbor::is_break(d)) {
    cbor::skip_cbor_value(d);  // key
    cbor::skip_cbor_value(d);  // value
}
```
This skips remaining entries so `m.close()` finds the break byte.

**Verification:** Unit test "overflow" encodes 10 features, verifies `decoded.valid == true` and `decoded.count == 8`. All 41 tests pass.

---

## Issue 10: `skip_cbor_value()` missing negative integers and float payloads (Medium) — RESOLVED

**Problem:** Major type 1 (negative integer) fell to `default:` which set datum null — forward-compat failure if future features use negative ints. Major type 7 (simple/float) only consumed the initial byte, missing float16 (2 bytes), float32 (4 bytes), and float64 (8 bytes) payloads — cursor misalignment and cascade failure.

**Fix:**
- Added `case negative_integer_type: { uint64 tmp{d, negative_integer_type}; }` — same length encoding as unsigned.
- Fixed simple_or_float_type to skip based on `additional_info()`: ai==24 → skip 1, ai==25 → skip 2, ai==26 → skip 4, ai==27 → skip 8.

**Verification:** Unit tests added for negative int (`0x38 0x63` = -100), float32 (`0xfa` + 4 bytes), float16 (`0xf9` + 2 bytes). All 41 tests pass.

---

## Issue 11: `datum::match()` UB on null datum, should use `strncmp` (Low) — RESOLVED

**Problem:** `match()` performed `while (d < data_end)` without null check. While `nullptr < nullptr` is technically defined (false) in C++17, it could trip UBSan. Also, the byte-by-byte loop missed compiler intrinsic optimization opportunities.

**Fix:** Rewrote to use `strncmp` (compiler intrinsic) with `is_readable()` guard and length equality check:
```cpp
bool match(const char *name) const {
    if (name == nullptr || !is_readable()) return false;
    size_t name_len = strlen(name);
    if (length() != (ssize_t)name_len) return false;
    return strncmp((const char *)data, name, name_len) == 0;
}
```

**Verification:** Existing `datum_match_unit_test` passes (includes null datum test case). All 41 tests pass.

---

## Issue 12: `text_string::construct()` UB on null datum (Low) — RESOLVED

**Problem:** `construct(datum{})` called `d.length()` which is `nullptr - nullptr` — undefined behavior per C++ standard (pointer subtraction only defined for pointers into same array). Callers pass `datum{}` for optional fields (e.g., username) frequently.

**Fix:** Added `is_readable()` guard at the top of `construct()`:
```cpp
static text_string construct(const datum &d) {
    if (!d.is_readable()) return text_string{};
    uint64 len{(uint64_t)d.length(), text_string_type};
    datum val{d};
    return text_string{len, val};
}
```
Returns default invalid `text_string` for null/empty datum. Callers' `is_valid()` checks handle this correctly.

**Verification:** All 41 unit tests pass including exposed_creds_token test (empty username).

---

## Issue 13: Stale comments in `cbor_metadata.hpp` and `cbor_messages.hpp` (Minor) — RESOLVED

**Problem:** Class-level comment in `cbor_metadata.hpp` said "Opens an outer indefinite map on reset()... closes the map on end_encode()" — but after the refactor, the caller handles map open/close via `cbor_object`. Comment in `cbor_messages.hpp` for crypto_cnsa said write() is only for the array path — but after the `if constexpr` fix, the CBOR path uses it differently.

**Fix:** Updated both comments to reflect actual lifecycle:
- `cbor_metadata.hpp`: "Manages the raw buffer; the caller is responsible for opening/closing the outer CBOR map via cbor_object."
- `cbor_messages.hpp`: "On the JSON path it is written inside the array. On the CBOR path the caller writes KEY separately before calling write()."

**Verification:** Documentation-only change, all 41 tests pass.

---

## Issue 14: SSH crypto assessment not emitting CBOR + `feature_written_` bug (Medium) — RESOLVED

**Problem (two sub-issues):**

1. **SSH CBOR missing:** The SSH operator in `do_crypto_assessment` used `if constexpr` to skip CBOR output entirely. SSH crypto assessment set attributes (`cnsa_2_0_non_conformant`) but wrote nothing to the CBOR buffer. The inspector received no SSH crypto metadata for enrichment.

2. **`feature_written_` driven by wrong signal:** `cbor_meta.set_feature_written()` was called based on `assessment_result.any()` (semantic result) and `exposed_creds_ret != none` — not actual CBOR emission. For SSH, `assessment_result.any()` was true (attributes set) but no CBOR was written, causing schema-only buffers to leak to the inspector.

**Design Decision:** Target-name branching with single class.

SSH has a fundamentally different negotiation structure from TLS: bidirectional per-direction cipher lists (`kex_algorithms`, `encryption_algorithms_client_to_server`, `encryption_algorithms_server_to_client`). Rather than creating a separate class or adding a wire-format discriminator field, the existing `crypto_cnsa_message` holds a superset of TLS + SSH fields. The `write()` and `decode()` methods branch on the target key name:
- `"offered"` → SSH structure (kex_not_allowed + client_to_server/server_to_client sub-objects)
- `"client"` / `"session"` → TLS structure (ciphersuites_not_allowed, groups_not_allowed, psk)

This is unambiguous because the target names are semantically defined by the underlying protocols (SSH RFC 4253 vs TLS). No explicit discriminator field is written to the wire or shown in output. The inspector already knows the protocol via `get_fingerprint_type(analysis_ctxt)` if needed.

**Fix (multi-part):**

1. **SSH fields in `crypto_cnsa_message`** (`cbor_messages.hpp`):
   - Added `kex_not_allowed_[]`, `c2s_cs_not_allowed_[]`, `s2c_cs_not_allowed_[]` arrays with `_allowed_` quantifier strings
   - Added datum-based setters (`add_kex_not_allowed(datum)`, etc.) to avoid dangling pointer from temporary `std::string`
   - Refactored `write()` into `write_tls_target()` and `write_ssh_target()` helpers, branching on `target_.value().match("offered")`
   - Refactored `decode()` into `decode_tls_target()` and `decode_ssh_target()` static helpers, branching on target key name

2. **SSH assess functions** (`crypto_assess.h`):
   - Added `assess(ssh_kex_init, crypto_cnsa_message&)` virtual overload to base `assessor`
   - Added `assess_ssh_kex_methods_msg()`, `assess_ssh_ciphers_c2s()`, `assess_ssh_ciphers_s2c()` to `quantum_safe` — populate feature class with datum directly from packet buffer
   - Unified `assess(ssh_kex_init, json_array&)` to use feature class + `msg.write<json_object, json_array>(a)`

3. **SSH CBOR emission** (`pkt_proc.cc`):
   - Added `assess_ssh()` helper template in `do_crypto_assessment` — mirrors `assess_tls()` but only uses CNSA (no NIST for SSH)
   - SSH operators (`ssh_init_packet`, `ssh_kex_init`) now call `assess_ssh()` which populates `cnsa_msg`, writes CBOR on the CBOR path

4. **`feature_written_` fix** (`pkt_proc.cc`):
   - Added `bool wrote_cbor_feature_` + accessor to both `do_crypto_assessment` and `check_exposed_creds`
   - Set flag after each successful CBOR write (in `assess_tls()`, `assess_ssh()`, `write_feature()`)
   - Replaced `if (assessment_result.any()) cbor_meta.set_feature_written()` with `if (crypto_visitor.wrote_cbor_feature()) cbor_meta.set_feature_written()`
   - Replaced `if (exposed_creds_ret != none) cbor_meta.set_feature_written()` with `if (creds_visitor.wrote_cbor_feature()) cbor_meta.set_feature_written()`
   - Applied in both CBOR branches (fingerprint-known and fingerprint-unknown paths)

**Wire format:**
```
TLS: {"policy":"quantum_safe","client":{"ciphersuites_not_allowed":[...],"groups_not_allowed":[...],"tls_cert_with_extern_psk":false}}
SSH: {"policy":"quantum_safe","offered":{"kex_not_allowed":[...],"kex_allowed":"none","client_to_server":{"ciphersuites_not_allowed":[...],"ciphersuites_allowed":"some"},"server_to_client":{...}}}
```

**Verification:**
- All 41 unit tests pass, `make test` passes (comparison + e2e)
- TLS JSON output unchanged from baseline
- SSH JSON output correct with full kex/cipher structure
- E2E: TLS metadata appears in Snort `unified.out` enrichment (SSH requires labeled VDB fingerprint for unified output, verified via snort.out attribute tag)
- `CBOR_NO_DATA` correctly returned for SSH-only attribute cases (feature_written_ fix working)
