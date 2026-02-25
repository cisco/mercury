#!/bin/bash

# definitions for colorized output
COLOR_RED="\033[0;31m"
COLOR_GREEN="\033[0;32m"
COLOR_YELLOW="\033[0;33m"
COLOR_OFF="\033[0m"

## script for fuzz testing pkt processing and protocol classes

export CC="clang"
export CXX="clang++"

parent_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

LIBMERC_FOLDER=../../src/libmerc/

USAGE="[-r <iterations> -t <time> -h <help> -n <none(run all test)/test_name>] -s <openssl_v1_1> -v <openssl_v3_0>"

default_runs=10000000000
default_time=200
specific_test="none"
coverage_enabled=""

total_headers=0
total_test_function=0
mkdir_fail=0
pass=0
fail=0
flags=""
openssl_v1_1="false"
openssl_v3_0="false"

#read command line args
#
while getopts hr:t:n:s:c:v: flag
do
    case "${flag}" in
        h) echo "$USAGE"
            exit 1;;
        r) default_runs=${OPTARG};;
        t) default_time=${OPTARG};;
        n) specific_test=${OPTARG};;
        s) openssl_v1_1=${OPTARG};;
        c) coverage_enabled=${OPTARG};;
        v) openssl_v3_0=${OPTARG};;
        \?) echo "ERROR: Invalid option: $USAGE"
            exit 1;;
    esac
done


if [[ "$coverage_enabled" -eq "1" ]]; then
    if [[ "$CFLAGS" == *"-O3"* ]]; then
        CFLAGS=$(echo "$CFLAGS" | sed -E 's/(^| )-O3( |$)/ /g')
    fi;
    flags+=" -fprofile-instr-generate -fcoverage-mapping -O0"
    LDFLAGS+=" -lgcov"
fi;

if [[ "$openssl_v3_0" == "true" ]]; then
    flags+=" -DOPENSSL_V3_0"
elif [[ "$openssl_v1_1" == "true" ]]; then
    flags+=" -DOPENSSL_V1_1"
fi;

XSIMD_INCLUDE="-I${parent_path}/../../src/libmerc/xsimd/include"
flags="$flags $XSIMD_INCLUDE"

cd $LIBMERC_FOLDER

# pre-cleanup: remove transient files from prior runs
rm -f "$parent_path"/*/.corpus_pre_count
rm -rf "$parent_path"/*/corpus.min
rm -f "$parent_path"/.minimize_*.log

# remove per-target transient files left by the current run
cleanup_transient_files () {
    rm -f "$parent_path"/*/.corpus_pre_count
}

# check results after running all the tests
check_result () {
    dir_name=$1;

    if [[ "$specific_test" != "none" ]]; then
        if [[ "$specific_test" != $dir_name ]]; then
            return 0;
        fi;
    fi;

    echo "checking dir $dir_name"
    if [[ ! -d "$parent_path/$dir_name" ]] ; then
        # dir creation failure was already counted in mkdir_fail by exec_testcase
        echo -e "${COLOR_RED} FAILED TEST : $dir_name (test dir not found)${COLOR_OFF}"
        return 1
    fi;

    cd $parent_path/$dir_name

    if [[ ! -d "./corpus" ]] ; then
        # dir creation failure was already counted in mkdir_fail by exec_testcase
        echo -e "${COLOR_RED} FAILED TEST : $dir_name (corpus dir not found)${COLOR_OFF}"
        cd ../$LIBMERC_FOLDER
        return 1;
    fi;

    if [[ ! -f "$dir_name.log" ]] ; then
        # no log means the fuzzer never launched (e.g. build failed); already counted in fail by exec_testcase
        cd ../$LIBMERC_FOLDER
        return 1;
    fi;

    if [[ $(grep -Ec "((ERROR)|(ABORTING))" $dir_name.log) -gt 0 ]]; then
        echo -e "${COLOR_RED} FAILED TEST : $dir_name${COLOR_OFF}"
        fail=$((fail+1))
    else
        echo -e "${COLOR_YELLOW} PASS : $dir_name${COLOR_OFF}"
        pass=$((pass+1))
    fi;

    post_corpus="$(ls ./corpus | wc -l)"
    pre_corpus=$(cat ./.corpus_pre_count 2>/dev/null || echo 0)
    if [[ "$post_corpus" -gt "$pre_corpus" ]]; then
        new_count=$((post_corpus - pre_corpus))
        echo -e "${COLOR_GREEN} corpus updated: $new_count new entries${COLOR_OFF}"
    fi;

    cd ../$LIBMERC_FOLDER;
}

# execute test case for a specific struct/class fuzz_test by looking in dir of same name
# report if struct/class has fuzz_test() but dir does not exist
exec_testcase () {
    dir_name=$1;
    fuzz_type=$3;

    #check for specific testcase case option
    if [[ "$specific_test" != "none" ]]; then
        if [[ "$specific_test" != $dir_name ]]; then
            echo "skipping test"
            return 0;
        fi;
    fi;

    echo "checking dir $dir_name"
    if [[ ! -d "$parent_path/$dir_name" ]] ; then
        echo -e "${COLOR_YELLOW} $dir_name test dir not found, creating it: $parent_path/$dir_name/corpus${COLOR_OFF}"
        if ! mkdir -p "$parent_path/$dir_name/corpus" ; then
            echo -e "${COLOR_RED} failed to create $dir_name test dir${COLOR_OFF}"
            mkdir_fail=$((mkdir_fail+1))
            return 1
        fi
    fi;

    cd $parent_path/$dir_name

    # generate the test .cc file
    echo "" > "fuzz_test_$dir_name.c"
    #echo "#include ../$LIBMERC_FOLDER/$2.h"

cat <<EOF >> "fuzz_test_$dir_name.c"
#include "../$LIBMERC_FOLDER$2"
EOF

if [[ "$fuzz_type" == "one" ]]; then
cat <<EOF >> "fuzz_test_$dir_name.c"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    return ${dir_name}_fuzz_test(Data, Size);
}
EOF

elif [[ "$fuzz_type" == "two" ]]; then
cat <<EOF >> "fuzz_test_$dir_name.c"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    size_t mid = Size / 2;

    const uint8_t *Data1 = Data;
    size_t Size1 = mid;

    const uint8_t *Data2 = Data + mid;
    size_t Size2 = Size - mid;

    return ${dir_name}_fuzz_2_test(Data1, Size1, Data2, Size2);
}
EOF
fi;

    # make fuzz_test
    $CXX -g -O0 -fno-omit-frame-pointer -x c++ -std=c++17 -fsanitize=fuzzer,address,leak ${flags} -I../../src/libmerc -Wno-narrowing -Wno-deprecated-declarations -L./.. "fuzz_test_$dir_name.c" -l:libmerc.a $LDFLAGS -lssl -lcrypto -lz -o "fuzz_${dir_name}_exec"
    if [[ ! -f "./fuzz_${dir_name}_exec" ]] ; then
        echo -e "${COLOR_RED} executable not built, failed test${COLOR_OFF}"
        fail=$((fail+1))
        cd ../$LIBMERC_FOLDER;
        return 1;
    fi;

    if [[ ! -d "./corpus" ]] ; then
        echo -e "${COLOR_YELLOW} $dir_name corpus dir not found, creating it${COLOR_OFF}"
        if ! mkdir -p "./corpus" ; then
            echo -e "${COLOR_RED} failed to create $dir_name corpus dir${COLOR_OFF}"
            mkdir_fail=$((mkdir_fail+1))
            cd ../$LIBMERC_FOLDER
            return 1;
        fi
    fi;

    chmod +x "fuzz_${dir_name}_exec"
    # save corpus entry count before run so check_result can compare per-test
    echo "$(ls ./corpus/ | wc -l)" > ./.corpus_pre_count

    # Wait if memory usage exceeds 80%
    while true; do
        mem_used_pct=$(free | awk '/^Mem:/ {printf "%.0f", ($3/$2)*100}')
        if [[ $mem_used_pct -lt 80 ]]; then
            break
        fi
        sleep 2
    done

    free -h | awk -v name="$dir_name" '/^Mem:/ {printf "Starting %s - Mem: %s used / %s total (%s available)", name, $3, $2, $7}'
    awk '{printf " - Load: %.2f\n", $1}' /proc/loadavg

    echo -e "${COLOR_YELLOW} ${dir_name} testcase in parallel${COLOR_OFF}"
    ./"fuzz_${dir_name}_exec" -seed=1 ./corpus/ -runs=$default_runs -max_total_time=$default_time > $dir_name.log 2>&1 &

    cd ../$LIBMERC_FOLDER;
}

# Corpus minimization via libFuzzer's merge mode (-merge=1).
#
# As fuzzing progresses, the corpus accumulates inputs that may become
# redundant — a newer input can cover a strict superset of the code
# paths exercised by an older one.  Merge mode re-evaluates every
# corpus entry's coverage contribution and copies only the minimal set
# of inputs needed to preserve total coverage into a fresh directory.
# This shrinks the corpus without losing any covered code paths, which
# speeds up future fuzz runs (fewer inputs to replay on startup) and
# keeps the committed corpus lean.
#
# Command-line usage (for a single target):
#   mkdir -p corpus.min
#   ./fuzz_dns_exec -merge=1 corpus.min corpus/
#   rm -rf corpus && mv corpus.min corpus
#
# The function below automates this for every target that was built.
minimize_corpus () {
    local total_targets=0
    local total_pre_fuzz=0
    local total_post_fuzz=0
    local total_post_min=0
    local total_removed=0

    echo ""
    echo "Minimizing corpus (before fuzzing -> after fuzzing -> after minimization):"

    for target_dir in "$parent_path"/*/; do
        local dir_name
        dir_name=$(basename "$target_dir")

        # skip if this target was not executed in this run (pre-cleanup
        # removes stale files, so only current-run targets have this marker)
        [[ -f "$target_dir/.corpus_pre_count" ]] || continue

        total_targets=$((total_targets + 1))
        local pre_fuzz
        pre_fuzz=$(cat "$target_dir/.corpus_pre_count" 2>/dev/null || echo 0)
        local post_fuzz
        post_fuzz=$(ls "$target_dir/corpus/" | wc -l)
        total_pre_fuzz=$((total_pre_fuzz + pre_fuzz))
        total_post_fuzz=$((total_post_fuzz + post_fuzz))

        # skip empty corpora
        if [[ $post_fuzz -eq 0 ]]; then
            echo "  $dir_name: $pre_fuzz -> $post_fuzz -> 0 (empty)"
            continue
        fi

        local merge_dir="$target_dir/corpus.min"
        rm -rf "$merge_dir"
        mkdir -p "$merge_dir"
        if "$target_dir/fuzz_${dir_name}_exec" -merge=1 "$merge_dir" "$target_dir/corpus/" > "$parent_path/.minimize_${dir_name}.log" 2>&1; then
            local post_min
            post_min=$(ls "$merge_dir" | wc -l)
            mv "$target_dir/corpus" "$target_dir/corpus.old"
            if mv "$merge_dir" "$target_dir/corpus"; then
                rm -rf "$target_dir/corpus.old"
            else
                # restore original corpus if swap failed
                mv "$target_dir/corpus.old" "$target_dir/corpus"
                rm -rf "$merge_dir"
            fi
            local removed=$((post_fuzz - post_min))
            total_post_min=$((total_post_min + post_min))
            total_removed=$((total_removed + removed))
            rm -f "$parent_path/.minimize_${dir_name}.log"
            if [[ $removed -gt 0 ]]; then
                echo "  $dir_name: $pre_fuzz -> $post_fuzz -> $post_min ($removed removed)"
            else
                echo "  $dir_name: $pre_fuzz -> $post_fuzz -> $post_min (already minimal)"
            fi
        else
            echo -e "${COLOR_RED}  $dir_name: merge failed (see .minimize_${dir_name}.log)${COLOR_OFF}"
            rm -rf "$merge_dir"
            total_post_min=$((total_post_min + post_fuzz))
        fi
    done

    echo ""
    echo "###############################################"
    echo "Corpus summary (before fuzzing -> after fuzzing -> after minimization)"
    echo "targets processed:    $total_targets"
    echo "before fuzzing:       $total_pre_fuzz"
    echo "after fuzzing:        $total_post_fuzz"
    echo "after minimization:   $total_post_min"
    echo "removed by minimization: $total_removed"
    echo "###############################################"

    if [[ $total_post_fuzz -gt 0 ]]; then
        echo ""
        echo "Corpus entries are minimized, coverage-essential inputs."
        echo "Consider committing them to improve future fuzz run coverage:"
        echo "  git add test/fuzz/*/corpus/ && git commit -m \"fuzz: update corpus\""
    fi
}

# check for libmerc.a
if [[ ! -f "./libmerc.a" ]]; then
    make libmerc.a
fi;
cp ./libmerc.a $parent_path/.


# scan all header files to look for matching {_fuzz_test} function definitions to extract class/testcase name
# testcase definition format : class_name_fuzz_test() or struct_name_fuzz_test()
# To create multiple fuzz targets for same class/struct, append an identification tag like number post class/struct name eg quic_init01_fuzz_test()
# and create a test dir for corpus with exact same name
for header in *.h *.hpp; do
    echo "check $header for test function"
    total_headers=$((total_headers+1))

    result1=$(grep -oE "\s(.+)_fuzz_test.*[^;]$" $header)
    while read -r line; do
        class=$(echo $line | grep -oE "\s(.+)_fuzz_test" | sed -nr 's/.* (.+)_fuzz_test/\1/p')
        echo "$class :"
        exec_testcase "$class" "$header" "one"
        total_test_function=$((total_test_function+1));
    done < <(echo "$result1" | grep -v "^$")

    result2=$(grep -oE "\s(.+)_fuzz_2_test.*[^;]$" $header)
    while read -r line; do
        class=$(echo $line | grep -oE "\s(.+)_fuzz_2_test" | sed -nr 's/.* (.+)_fuzz_2_test/\1/p')
        echo "$class :"
        exec_testcase "$class" "$header" "two"
        total_test_function=$((total_test_function+1));
    done < <(echo "$result2" | grep -v "^$")

done

# wait for parallel running tests to exit
wait

for header in *.h *.hpp; do
    result=$(grep -oE "\s(.+)(_fuzz_test|_fuzz_2_test).*[^;]$" $header)
    while read -r line; do
        class=$(echo $line | grep -oE "\s(.+)(_fuzz_test|_fuzz_2_test)" | sed -nr 's/.* (.+)(_fuzz_test|_fuzz_2_test)/\1/p')
        check_result "$class" "$header"
    done < <(echo "$result" | grep -v "^$")

done

echo ""
echo "###############################################"
echo "Test run statistics"
echo "headers $total_headers"
echo "fuzz_test functions $total_test_function"
echo -e "${COLOR_GREEN} pass $pass${COLOR_OFF}"
echo -e "${COLOR_RED} fail $fail${COLOR_OFF}"
if [[ ! "$mkdir_fail" -eq "0" ]]; then
    echo -e "${COLOR_RED} mkdir_fail $mkdir_fail${COLOR_OFF}"
fi
echo "###############################################"

# Nonzero exit code if any failures; skip corpus management
if [[ $fail -ne 0 || $mkdir_fail -ne 0 ]]; then
    cleanup_transient_files
    exit 1
fi

minimize_corpus
cleanup_transient_files
