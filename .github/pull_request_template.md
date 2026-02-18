## Changelog Entry

One-line summary.

## Description

Problem, root cause, solution.

## Sample Output

Sample JSON or other output.
```json
{"foo":2,"bar":"baz"}
```

## Checklist

<!-- Delete items that don't apply. -->

- Configuration
  - [ ] Command line option(s)
  - [ ] Config file option(s)
- Testing
  - [ ] Add pcap and/or unit test function; update test resources file if needed
  - [ ] Fuzz-test, unit-test, and document any new function that accesses a data pointer
  - [ ] Run on live traffic - new protocol data appears in expected quantity
  - [ ] Run on live traffic - existing protocol data is not suppressed
- Output and Schema Changes
  - [ ] Follow JSON output guidelines (see `doc/guidelines.md`)
  - [ ] Schema changes reviewed by stakeholders
  - [ ] Estimate % increase in size of JSON output based on suitable reference pcap
- Documentation
  - [ ] Update `--help`
  - [ ] Update `README.md` (includes output of `--help`)
