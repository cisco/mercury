#!/bin/bash
# Build a binary package of mercury. Supports deb and rpm.

usage() {

    echo -e "$0 [ -h ] | [ -v version ] [ -t deb|rpm ]\n"
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

FPM_LINUX_OPTIONS="-n mercury -v $VERSION --iteration $ITERATION\
    --vendor Cisco -m etta@cisco.com --url https://github.com/cisco/mercury \
    --after-install ./install_mercury/postinstall \
    --config-files /etc/mercury/mercury.cfg"

if [ "$BUILDTYPE" == "deb" ]; then
    fpm -s dir -t deb $FPM_LINUX_OPTIONS \
        --deb-systemd ./install_mercury/mercury.service \
        --deb-no-default-config-files \
        --description "Mercury is an experimental single-purpose network security monitoring application focusing on traffic fingerprinting." \
        --after-remove ./install_mercury/postuninstall_remove \
        --deb-after-purge ./install_mercury/postuninstall_purge \
        ./src/mercury=/usr/local/bin/ mercury.cfg=/etc/mercury/ \
        ./resources/pyasn.db=/usr/local/share/mercury/ ./resources/fingerprint_db.json.gz=/usr/local/share/mercury/
elif [ "$BUILDTYPE" == "rpm" ]; then
    fpm -s dir -t rpm $FPM_LINUX_OPTIONS \
        --rpm-dist el7 \
        --rpm-attr 775,mercury,mercury:/usr/local/var/mercury \
        --description "Mercury is an experimental single-purpose network security monitoring application focusing on traffic fingerprinting." \
        --after-remove ./install_mercury/postuninstall_rpm \
        ./install_mercury/mercury.service=/usr/lib/systemd/system/ \
        ./src/mercury=/usr/local/bin/ mercury.cfg=/etc/mercury/ \
        ./resources/pyasn.db=/usr/local/share/mercury/ ./resources/fingerprint_db.json.gz=/usr/local/share/mercury/
fi
