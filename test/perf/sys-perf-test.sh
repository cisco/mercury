#!/bin/sh

# echo "testing performance of filesystem and storage devices"

# set target directory and tmpfile in that directory
#
DIR=$PWD
TMPFILE=$DIR/tmpfile

# determine the device associated with the target filesystem
#
DEV=$(df ${DIR} | egrep -o "/dev/[a-z]*")
DEVBASE=$(basename ${DEV})

# get system description
UNAME=$(uname -svrm)
FS=$(df --output=fstype . | tail -n 1)

FNAME=$(echo ${UNAME}-${FS}-${DEV}.txt | tr " " "-" | tr -d "/")

# clear OS and drive caches
#
# hdparm -F ${DEV}
sync
echo 3 > /proc/sys/vm/drop_caches

# the following command turns off the device's page cache - only use this if you know how to turn it back on!
# hdparm -W0 ${DEV}

# run performance tests
#
WRITEPERF=$(dd if=/dev/zero of=${TMPFILE} oflag=direct conv=fdatasync bs=1M count=10K 2>&1 | egrep -o "[0-9.]* [KMG]*B/s")

# clear OS and drive caches again
#
# hdparm -F ${DEV}
sync
echo 3 > /proc/sys/vm/drop_caches

READPERF=$(dd if=${TMPFILE} of=/dev/null conv=fdatasync bs=1M count=10K 2>&1 | egrep -o "[0-9.]* [KMG]*B/s")

# remove temporary file
rm -f ${TMPFILE}

# report results
#
> ${FNAME}
echo ${UNAME} >> ${FNAME}
echo ${FS} >> ${FNAME}
echo ${DEV} >> ${FNAME}
echo "write throughput for "$DIR ":" ${WRITEPERF} >> ${FNAME}
echo "read throughput for "$DIR ": " ${READPERF} >> ${FNAME}

# change file owner/group to non-root
#
chown ${SUDO_USER}:${SUDO_USER} ${FNAME}


