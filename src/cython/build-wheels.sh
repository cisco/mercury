#!/bin/bash

# docker run --rm -v /home/ubuntu/mercury-transition-clean:/mercury:rw quay.io/pypa/manylinux_2_28_x86_64:latest /mercury/src/cython/build-wheels.sh


function repair_wheel {
    wheel="$1"
    if ! auditwheel show "$wheel"; then
        echo "Skipping non-platform wheel $wheel"
    else
        auditwheel repair "$wheel" --plat manylinux_2_28_x86_64 -w /mercury/src/cython/wheelhouse/
    fi
}

# Install a system package required by our library
yum install -y openssl-devel make zlib-devel

# configure and make mercury
cd /mercury
make clean
./configure
make
cd -

# set environment variables
FLAGS='-DSSLNEW'
export ENV_CFLAGS=${FLAGS}

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
