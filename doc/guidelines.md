## Best Practices for JSON Output



This note provides guidance for developers of code that generates JSON output, with the goals of producing JSON that works well with Parquet and `jq`.

#### Principles

- All names and strings must be valid UTF-8 with JSON characters escaped.
- Data from packets is not trusted to be in the correct format.
- No spaces or dashes in names.
- Prefer lowercase.
- There should be no empty JSON objects
- For compressibility, highly variable fields (e.g. IP.ID) should be at the tail end of a record, not the front.
- Avoid using network data as JSON keys, so that keys are consistent (and thus parquet-friendly) and follow the other guidelines.
- There should be no empty JSON arrays (if semantically necessary, exceptions can be made if we pre-deploy the json2parquet schema).

#### Resources

The class utf8_safe_string
https://wwwin-github.cisco.com/network-intelligence/mercury-transition/blob/dev/src/libmerc/utf8.hpp#L931
can be used to safely convert packet data into a string that can be
used as e.g. a JSON array or object name.
