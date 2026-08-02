#!/bin/bash
# genhtml --criteria-script hook. Invoked as: SCRIPT <name> <type> <json-string>
# At type=top, dumps the per-line TLA counts for cov_diff_report.py; never gates.
# E.g., <json-string> = {"line":{"GNC":3,"UNC":1,"CBC":10}}
[ "$2" = "top" ] && printf '%s' "$3" > "${COV_TLA_OUT:-/tmp/cov-tla.json}"
exit 0
