#!/bin/bash
# Build a binary package of mercury. Supports deb and rpm.

usage() {

    echo -e "$0 [ -h ] | [ -v version ] [ -t deb|rpm]\n"
    echo -e "usage:\n"
    echo "-h) prints usage information and exits"
    echo "-v) specifies the version of the package to be built. MANDATORY and should be in the form of Major.Minor"
    echo "-i) specifies the build iteration (optional)"
    echo -e "-t) specifices which package to build (rpm, deb)\n"
}

while getopts "ht:v:i:" arg; do
    case $arg in
    h)
        usage
        exit
        ;;
    v)
        echo "-v was triggered with option ${OPTARG}"
        VERSION=${OPTARG}
        ;;
    i)
        echo "-i was triggered with option ${OPTARG}"
        ITERATION=${OPTARG}
        ;;

    t)
        echo "-t was triggered with option ${OPTARG}"
        BUILDTYPE=${OPTARG}
        ;;
    \?)
        echo "error: invalid option -${OPTARG}"
        usage
        exit 1
        ;;
    :)
        echo "error: option -${OPTARG} requires an argument"
        usage
        exit 1
        ;;
    esac
done
if [ $(($# + 1)) != "${OPTIND}" ]; then
    echo "error: illegal option"
    usage
    exit 1
fi
if [ -z "$VERSION" ]; then
    VERSION="$(cat VERSION)"
fi
if [ -z "$BUILDTYPE" ]; then
    echo "-t deb|rpm must be specified" >&2
    exit 1
fi

if [ -z "$ITERATION" ]; then
    ITERATION="1"
fi

DESCRIPTION="Mercury: a tool for network metadata capture and analysis."

FPM_LINUX_OPTIONS="-v $VERSION --iteration $ITERATION\
    -m mercury-interest@cisco.com --url https://github.com/cisco/mercury \
    --after-install ./install_mercury/postinstall \
    --config-files /etc/mercury/mercury.cfg       \
    --license BSD"

if [ "$BUILDTYPE" == "deb" ]; then

    # Package name examples:
    #   ubuntu 24.04 -> mercury-u24
    #   debian 13    -> mercury-d13
    #   other        -> mercury-<id><version> (e.g., mercury-foo3_14)

    # Source os-release to get OS information (fallback if unavailable)
    if [ -r /etc/os-release ]; then
        source /etc/os-release
    else
        ID="unknown"
        VERSION_ID=""
    fi

    # Determine package name suffix based on OS
    if [ "$ID" == "ubuntu" ]; then
        # Extract major version (e.g., "24.04" -> "24")
        MAJOR_VERSION=$(echo "$VERSION_ID" | cut -d. -f1)
        PKG_SUFFIX="-u${MAJOR_VERSION}"
    elif [ "$ID" == "debian" ]; then
        # Debian VERSION_ID is already just the major version (e.g., "13")
        PKG_SUFFIX="-d${VERSION_ID}"
    else
        # For other distributions, use ID and VERSION_ID with space converted to underscore
        CLEAN_VERSION_ID=$(echo "$VERSION_ID" | tr ' ' '_')
        PKG_SUFFIX="-${ID}${CLEAN_VERSION_ID}"
    fi

    # Determine libssl version for dependency and print diagnostic info
    if dpkg -s libssl1.1 > /dev/null 2>&1; then
        SSL_LIB=libssl1.1
        echo "found libssl1.1"
    else
        SSL_LIB=libssl3
        echo "assuming libssl3"
    fi

    PKG_NAME="mercury${PKG_SUFFIX}"
    echo "building package: $PKG_NAME for $ID $VERSION_ID"
    fpm -s dir -t deb -n $PKG_NAME $FPM_LINUX_OPTIONS \
        --depends $SSL_LIB \
        --depends zlib1g    \
        --deb-systemd ./install_mercury/mercury.service \
        --deb-no-default-config-files \
        --description "$DESCRIPTION" \
        --after-remove ./install_mercury/postuninstall_remove \
        --deb-after-purge ./install_mercury/postuninstall_purge \
        ./src/mercury=/usr/local/bin/ mercury.cfg=/etc/mercury/ \
        ./mercury=/usr/share/bash-completion/completions/

elif [ "$BUILDTYPE" == "rpm" ]; then

    # note: we could detect libssl version here

    # detect platform ID (e.g., "el8" or "el9")
    source /etc/os-release
    ELX=$(echo $PLATFORM_ID | cut -f2 -d:)

    fpm -s dir -t rpm -n mercury $FPM_LINUX_OPTIONS \
        --depends 'openssl' \
        --depends 'zlib'    \
        --rpm-dist $ELX \
        --rpm-attr 775,mercury,mercury:/usr/local/var/mercury \
        --description "$DESCRIPTION" \
        --after-remove ./install_mercury/postuninstall_rpm \
        ./install_mercury/mercury.service=/usr/lib/systemd/system/ \
        ./src/mercury=/usr/local/bin/ mercury.cfg=/etc/mercury/
fi
