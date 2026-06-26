#!/bin/bash
#
# test_intercept.sh
#
# tests the intercept.so library

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$script_dir/.." && pwd)

absolute_path() {
    local path=$1
    local dir
    local base

    dir=$(dirname "$path")
    base=$(basename "$path")
    if [ -d "$dir" ]; then
        printf "%s/%s\n" "$(cd "$dir" && pwd)" "$base"
    else
        printf "%s\n" "$path"
    fi
}

if [ -n "${BUILD_VARIANT:-}" ]; then
    build_variant=$BUILD_VARIANT
else
    build_variant=${BUILD_TYPE:-RelWithDebInfo}
    if [ -n "${SANITIZE:-}" ]; then
        build_variant="$build_variant+${SANITIZE//,/+}"
    fi
    if [ -n "${VISIBILITY:-}" ]; then
        build_variant="$build_variant+vis$VISIBILITY"
    fi
    if [ -n "${STATIC_CFG:-}" ]; then
        build_variant="$build_variant+staticcfg$STATIC_CFG"
    fi
fi
build_dir=${BUILD_DIR:-"$repo_root/build/$build_variant"}

default_libmerc_dir="$build_dir/lib"
if [ ! -d "$default_libmerc_dir" ] && [ -d "$repo_root/src/libmerc" ]; then
    default_libmerc_dir="$repo_root/src/libmerc"
fi
LIBMERC_DIR=${LIBMERC_DIR:-"$default_libmerc_dir"}
if [ -d "$LIBMERC_DIR" ]; then
    LIBMERC_DIR=$(cd "$LIBMERC_DIR" && pwd)
fi

INTERCEPT_SO=${INTERCEPT_SO:-"$LIBMERC_DIR/intercept.so"}
if [ ! -f "$INTERCEPT_SO" ] && [ -f "$repo_root/src/intercept.so" ]; then
    INTERCEPT_SO="$repo_root/src/intercept.so"
fi
INTERCEPT_SO=$(absolute_path "$INTERCEPT_SO")

INTERCEPT_SERVER=${INTERCEPT_SERVER:-"$build_dir/bin/intercept_server"}
if [ ! -x "$INTERCEPT_SERVER" ] && [ -x "$repo_root/src/intercept_server" ]; then
    INTERCEPT_SERVER="$repo_root/src/intercept_server"
fi
INTERCEPT_SERVER=$(absolute_path "$INTERCEPT_SERVER")

retain=0
if [ $# -eq 1 ]; then
    if [ $1 == "--retain" ]; then
        retain=1
    else
        echo "usage: $0 [--retain]"
        exit 1
    fi
fi

# verify that applications are installed
#

get_path() {
    EXE=$1
    TMP=`whereis -b $EXE`
    arrIN=(${TMP// / })
    BIN=${arrIN[1]}
    if [ "$BIN" == "" ]; then
        echo "warning: $TMP not found" >&2
        return 1
    fi
    echo $BIN
    return 0
}

WGET=$(get_path wget)                  #|| exit 1
CURL=$(get_path curl)                  #|| exit 1
FIREFOX=$(get_path firefox)            #|| exit 1
CHROME=$(get_path google-chrome)       #|| exit 1
EPIPHANY=$(get_path epiphany)          #|| exit 1
KONQUERER=$(get_path konqueror)        #|| exit 1


echo "testing intercept.so library for plaintext interception"

# set up shell variables, and change working directory
#
export intercept_output_type="daemon"
export intercept_output_level="full"
intercept_dir="$script_dir/tmpdir"
LD_PRELOAD="$INTERCEPT_SO"
mkdir -p "$intercept_dir"
echo "using output directory $intercept_dir"
echo "using intercept library $LD_PRELOAD"
echo "using libmerc directory $LIBMERC_DIR"
cd "$intercept_dir"

case "$(uname)" in
    Darwin) export DYLD_LIBRARY_PATH="$LIBMERC_DIR${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" ;;
    *)      export LD_LIBRARY_PATH="$LIBMERC_DIR${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" ;;
esac

# verify that library is present
#
if [ ! -f "$LD_PRELOAD" ]; then
    echo "error: file $LD_PRELOAD not found"
    exit 1
fi

if [ ! -x "$INTERCEPT_SERVER" ]; then
    echo "error: executable $INTERCEPT_SERVER not found"
    exit 1
fi

# start intercept_server, to collect output and write it to the file
# intercept.json
#
"$INTERCEPT_SERVER" intercept.json & echo $! > intercept_server.PID

sites=(accounts.google.com amazon.com apple.com bbc.com bp.blogspot.com cloudflare.com cnn.com creativecommons.org developers.google.com docs.google.com drive.google.com dropbox.com en.wikipedia.org es.wikipedia.org europa.eu facebook.com fr.wikipedia.org github.com google.de googleusercontent.com gstatic.com issuu.com istockphoto.com line.me linkedin.com mail.google.com maps.google.com mozilla.org myspace.com netvibes.com paypal.com play.google.com plus.google.com sites.google.com support.google.com t.me uol.com.br vimeo.com vk.com whatsapp.com who.int wordpress.org www.blogger.com www.google.com www.yahoo.com youtu.be youtube.com)

short_list_sites=(www.google.com)

# start interception by exporting variables
#
export intercept_dir
export LD_PRELOAD

run() {
    "$1" "${@:2}" >> "$1".txt 2>&1 & echo $! > "$1".PID && sleep 5 && kill $(cat "$1".PID); rm "$1".PID
}

# loop over sites
#
echo "looping over all web servers"
blank="                                                       "
for s in ${short_list_sites[@]}; do
    echo -ne "visiting $s $blank \r\c" >> /dev/stderr
    run wget --prefer-family=IPv6 https://$s  &
    run curl --verbose https://$s > $s.curl   &
    run firefox https://$s                    &
    run google-chrome https://$s              &
    run epiphany https://$s                   &
    run konqueror https://$s                  &
done
echo "done $blank"

# run some tools
#
apt-get download g++


# stop interception by re-setting LD_PRELOAD
#
export LD_PRELOAD=""

# shut down intercept_server, after a pause to give JSON
# output time to get into file
#
# note: the sleep interval used below should exceed that used in the
# 'run' function above
#
sleep 7
kill -s INT `cat intercept_server.PID`
rm intercept_server.PID
sleep 1

# verify that output JSON file is valid
jq . intercept.json > /dev/null
retval=$?
if [ retval==0 ]; then
    echo "intercept JSON output is valid"
else
    echo "error: intercept JSON output is not valid"
    echo "retaining output files"
    exit 1
fi

# back to original directory
#
cd ..

# remove or retain the tmpdir/ directory, based on command line option
#
if [ $retain == "1" ]; then
    echo "retaining files"
else
    rm -rf tmpdir/
fi

# EOF
