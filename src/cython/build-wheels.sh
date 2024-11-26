#!/bin/bash

# docker run --rm -v /home/ubuntu/mercury-transition-clean:/mercury:rw quay.io/pypa/manylinux_2_28_x86_64:latest /mercury/src/cython/build-wheels.sh


function repair_wheel {
    wheel="$1"
    if ! auditwheel show "$wheel"; then
        echo "Skipping non-platform wheel $wheel"
    else
        auditwheel repair "$wheel" --plat manylinux2014_x86_64 -w /mercury/src/cython/wheelhouse/
    fi
}

# update outdated centos mirrors
sed -i -e 's/mirrorlist/#mirrorlist/g' \
    -e 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' \
    /etc/yum.repos.d/CentOS-*

#        -e 's|baseurl=http://vault.centos.org/centos|baseurl=http://vault.centos.org/altarch|g' \

# Install a system package required by our library
yum install -y openssl-devel make zlib-devel wget

# get latest openssl
wget https://github.com/openssl/openssl/releases/download/openssl-3.0.14/openssl-3.0.14.tar.gz
tar -xzvf openssl-3.0.14.tar.gz
cd openssl-3.0.14
./config --prefix=/usr --openssldir=/etc/ssl --libdir=lib no-shared zlib-dynamic
make
make install
echo "export LD_LIBRARY_PATH=/usr/local/lib:/usr/local/lib64" > /etc/profile.d/openssl.sh
source /etc/profile.d/openssl.sh
openssl version -a

# configure and make mercury
cd /mercury
make clean
./configure
make
cd -

# set environment variables
#FLAGS='-DSSLNEW'
#export ENV_CFLAGS=${FLAGS}

# Compile wheels
for PYBIN in /opt/python/*/bin; do
    # clean up cython directory
    cd /mercury/src/cython
    make clean
    rm -r mercury_python.egg-info/
    rm -r build/
    cd -

    "${PYBIN}/pip" install -r /mercury/src/cython/requirements.txt
    "${PYBIN}/pip" wheel /mercury/src/cython/ --no-deps -w /mercury/src/cython/wheelhouse/
done

# Bundle external shared libraries into the wheels
for whl in /mercury/src/cython/wheelhouse/*.whl; do
    repair_wheel "$whl"
done
