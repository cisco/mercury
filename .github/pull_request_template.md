## Description

Replace this description. What change is being made? (one-line TLDR summary)

Why are these changes being made?  Provide context and any design decisions that
are not reflected in the source code.  One good framing: problem, root cause,
solution.

## Sample Output

Sample JSON or other output.
```json
{"foo":2,"bar":"baz"}
```

## Checklist

<!-- If not applicable, append with "- N/A" and check the box. -->

- Configuration
  - [ ] Command line option(s)
  - [ ] Config file option(s)
- Testing
  - [ ] Add pcap and/or unit test function
  - [ ] Run on live traffic - new protocol data appears in expected quantity
  - [ ] Run on live traffic - existing protocol data is not suppressed
- Output and Schema Changes
  - [ ] Follow JSON output guidelines (see `doc/guidelines.md`)
  - [ ] Schema changes reviewed by stakeholders
  - [ ] Estimate % increase in size of JSON output based on suitable reference pcap
- Documentation
  - [ ] Update `--help`
  - [ ] Update `README.md` (includes output of `--help`)

## Changelog Entry

Replace this with the text to be included in `doc/CHANGELOG.md`, so that
reviewers can check the changelog entry for completeness and spelling.  Once
this PR is approved, add this entry to `doc/CHANGELOG.md` and commit it just
before merging the PR.
