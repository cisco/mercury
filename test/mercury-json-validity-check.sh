#!/bin/bash
#
# mercury-json-validity-check.sh
#
#
# usage: mercury-json-validity-check.sh <option1> <option2> ...
#
# to change the input files, export the shell variable INPUT before
# calling this script, for instance:
#
#   $ export INPUT=pcap; ./mercury-json-validity-check --certs-json --dns-json


MERCURY=../src/mercury

if [[ -z "${INPUT}" ]]; then
    INPUT=data/top-https.pcap
fi

option_array=("$@")

# test with no options
echo "testing mercury JSON output validity with no options"
$MERCURY -r $INPUT | jq . > /dev/null

# test with all permutations of options
for (( length=1; length <= "${#option_array[@]}"; ++length )); do
    for (( start=0; start + length <= "${#option_array[@]}"; ++start )); do
        options="${option_array[@]:start:length}"
        echo "testing mercury JSON output validity with options $options"
        $MERCURY -r $INPUT $options | jq . > /dev/null
        if [ $? -ne 0 ]; then
            echo "error: jq returned error code $?"
            exit 255
        fi
    done
done

# test with all permutations of options, with --analysis and --resources
extra_options="--analysis --resources=../resources/resources.tgz"
for (( length=1; length <= "${#option_array[@]}"; ++length )); do
    for (( start=0; start + length <= "${#option_array[@]}"; ++start )); do
        options="${option_array[@]:start:length}"
        echo "testing mercury JSON output validity with options $options $extra_options"
        $MERCURY -r $INPUT $options $extra_options | jq . > /dev/null
        if [ $? -ne 0 ]; then
            echo "error: jq returned error code $?"
            exit 255
        fi
    done
done
