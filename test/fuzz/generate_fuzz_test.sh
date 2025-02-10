#!/bin/bash

# definitions for colorized output
COLOR_RED="\033[0;31m"
COLOR_GREEN="\033[0;32m"
COLOR_YELLOW="\033[0;33m"
COLOR_OFF="\033[0m"

## makefile for fuzz testing pkt processing and protocol classes

export CC="clang"
export CXX="clang++"

parent_path=$( cd "$(dirname "${BASH_SOURCE[0]}")" ; pwd -P )

LIBMERC_FOLDER=../../src/libmerc/

USAGE="[-r <iterations> -t <time> -h <help> -n <none(run all test)/test_name>] -s <(true)newer openssl>"

default_runs=10000000000
default_time=200
specific_test="none"
coverage_enabled=""

total_headers=0
total_test_function=0
total_missing_dir=0
pass=0
fail=0
flags=""
openssl_new="false"

#read command line args
#
while getopts hr:t:n:s:c: flag
do
    case "${flag}" in
        h) echo "$USAGE"
            exit 1;;
        r) default_runs=${OPTARG};;
        t) default_time=${OPTARG};;
        n) specific_test=${OPTARG};;
        s) openssl_new=${OPTARG};;
        c) coverage_enabled=${OPTARG};;
        \?) echo "ERROR: Invalid option: $USAGE"
            exit 1;;
    esac
done

#specific_test="none"

if [[ "$coverage_enabled" -eq "1" ]]; then
    flags+=" -fprofile-instr-generate -fcoverage-mapping -O0"
    LDFLAGS+=" -lgcov"
fi;

if [[ "$openssl_new" -eq "true" ]]; then
    flags+=" -DSSLNEW"
fi;

XSIMD_INCLUDE="-I${parent_path}/../../src/libmerc/xsimd/include"
flags="$flags $XSIMD_INCLUDE"

cd $LIBMERC_FOLDER

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
        return 1
    fi;

    cd $parent_path/$dir_name

    if [[ $(grep -Ec "((ERROR)|(ABORTING))" $dir_name.log) -gt 0 ]]; then
        echo -e $COLOR_RED "FAILED TEST : $dir_name" $COLOR_OFF
        fail=$((fail+1))
    else
        echo -e $COLOR_YELLOW "PASS : $dir_name" $COLOR_OFF
        pass=$((pass+1))
    fi;

    post_corpus="$(ls ./corpus | wc -l)"
    if [[ "$post_corpus" -gt "$pre_corpus" ]]; then
        echo -e $COLOR_GREEN "corpus updated" $COLOR_OFF
    fi;

    cd corpus
    ls -1 | grep -v 'seed' | xargs rm -f
    cd ..

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
        echo -e $COLOR_RED "$dir_name test dir not found" $COLOR_OFF
        total_missing_dir=$((total_missing_dir+1))
        return 1
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
        echo -e $COLOR_RED "executable not built, failed test" $COLOR_OFF
        fail=$((fail+1))
        cd ../$LIBMERC_FOLDER;
        return 1;
    fi;

    if [[ ! -d "./corpus" ]] ; then
        echo -e $COLOR_RED "$dir_name test dir corpus not found" $COLOR_OFF
        total_missing_dir=$((total_missing_dir+1))
        cd ../$LIBMERC_FOLDER
        return 1;
    fi;

    chmod +x "fuzz_${dir_name}_exec"
    # count corpus pre test
    pre_corpus="$(ls ./corpus/ | wc -l)"
    echo -e $COLOR_YELLOW "${dir_name} testcase in parallel" $COLOR_OFF
    ./"fuzz_${dir_name}_exec" -seed=1 ./corpus/ -runs=$default_runs -max_total_time=$default_time > $dir_name.log 2>&1 &

    cd ../$LIBMERC_FOLDER;
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
if [[ ! "$total_missing_dir" -eq "0" ]]; then
    echo -e $COLOR_RED "missing test dir $total_missing_dir" $COLOR_OFF
fi
echo -e $COLOR_GREEN "pass $pass" $COLOR_OFF
echo -e $COLOR_RED "fail $fail" $COLOR_OFF
echo "###############################################"

# Nonzero exit code if any failures
if [[ $fail -ne 0 ]]; then
    exit 1
fi
