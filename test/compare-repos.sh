#!/bin/bash
#
# compare-repos.sh
#
# compares mercury in this repo with a different repo, by running the
# same arguments and then running diff on the resulting JSON

# default variables
#
MERC_PATH=../
ALT_MERC_PATH=""
PCAP=./data/top-https.pcap
RESOURCES=./data/resources-test.tgz
VERBOSE=false
HELP=false

while getopts "d:p:r:vh" opt; do
  case ${opt} in
    d)
        ALT_MERC_PATH=${OPTARG}
      ;;
    p)
        PCAP=${OPTARG}
      ;;
    r)
        RESOURCES=${OPTARG}
      ;;
    v)
        VERBOSE=true
      ;;
    h)
        HELP=true
        ;;
    ?)
        HELP=true
      ;;
  esac
done

if [ -z "${ALT_MERC_PATH}" ]; then
    if ! $HELP; then
       echo "error: -d option is required"
    fi
    HELP=true
fi

if $HELP; then
    echo "usage: $0 [-d <directory>][-p <PCAP>][-r <resources>][-v]-h]"
    echo

    echo "   Runs mercury from two different git repos (this one, and one specified with the -d flag)"
    echo "   on the same PCAP, with the same resources, and computes the diff of the resulting JSON files."
    echo "   The output file names have the format <branch>-<commit hash>.json.  The file diff.json is a"
    echo "   JSON file that represents the lines that differ in the two output files; the even lines"
    echo "   appeared in the output file corresponding to this repo, and the odd lines appeared in the"
    echo "   output file corresponding to the other repo."
    echo
    echo "  -d <directory> sets the directory of the alternate mercury repo"
    echo "  -p <PCAP>      sets the input PCAP to use in comparison (default: $PCAP)"
    echo "  -r <resources> sets the resource archive to use in comparison (default: $RESOURCES)"
    echo "  -v             causes verbose output"
    echo "  -h             outputs this help message"
    echo
    exit 0
fi

if [ ! -d $MERC_PATH ]; then
    echo "error: directory not found:" $MERC_PATH
    exit 1
fi
if [ ! -d $ALT_MERC_PATH ]; then
    echo "error: directory not found:" $ALT_MERC_PATH
    exit 1
fi

BASENAME=$(git rev-parse --abbrev-ref HEAD)
NAME=$BASENAME"-"$(git rev-parse --short HEAD)

ALT_BASENAME=$(cd $ALT_MERC_PATH && git rev-parse --abbrev-ref HEAD)
ALT_NAME=$ALT_BASENAME"-"$(cd $ALT_MERC_PATH && git rev-parse --short HEAD)

if [ "$NAME" == "$ALT_NAME" ]; then
    echo "error: " $MERC_PATH "and" $ALT_MERC_PATH "have the same git branch and commit ($NAME)"
    exit 1
fi

# verbose output
#
if $VERBOSE; then
    echo comparing $NAME and $ALT_NAME
    echo "alternate mercury path: $ALT_MERC_PATH"
    echo "packet capture file:    $PCAP"
    echo "resource archive:       $RESOURCES"
fi

# verify paths
#
if [ ! -f $MERC_PATH/src/mercury ]; then
    echo "error: file not found:" $MERC_PATH/src/mercury
    exit 1
fi
if [ ! -f $ALT_MERC_PATH/src/mercury ]; then
    echo "error: file not found:" $ALT_MERC_PATH/src/mercury
    exit 1
fi

ANALYSIS="--analysis --resources $RESOURCES"

COMMANDS=" --read $PCAP --metadata --dns-json --certs-json $ANALYSIS"

$MERC_PATH/src/mercury      $COMMANDS > $NAME.json
$ALT_MERC_PATH/src/mercury  $COMMANDS > $ALT_NAME.json

# compute the diff of the two JSON files, using sed to tweak the
# output so that successive lines of the output file represent
# differing lines of $NAME.json (top) and $ALT_NAME.json (bottom)
#
diff $NAME.json $ALT_NAME.json | sed - -e 's/< //' -e '/---/d' -e 's/> //' -e '/^[a-z0-9,]*$/d' > diff-$NAME-$ALT_NAME.json





