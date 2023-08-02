###
## This Dockerfile provides an easy way to try mercury.
#
# Run this once:
#   docker build -t mercury:default .
#
# Run mercury:
#   docker run --rm -i --entrypoint /usr/local/bin/mercury \
#       --volume .:/root mercury:default <args> <for> <mercury>
#
# You can then set this as a bash alias in your .bashrc:
#   alias mercury='docker run --rm -i --entrypoint /usr/local/bin/mercury --volume .:/root mercury:default'
#
# In each of the commands above, feel free to replace name of the docker image
# (mercury:default) with a different name/tag of your choosing, as long as it
# remains consistent across the commands.
#
# The host's current working directory (.) will be mounted as the container's
# current working directory (/root).  This provides mercury some read and write
# access to the host filesystem, such as a pcap file in your current directory.

FROM alpine:latest
RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/testing/" >> /etc/apk/repositories && \
    apk update && \
    apk add --no-cache build-base git make gcc g++ linux-headers pkgconfig \
    wget tar zlib-dev openssl-dev musl-dev libc-dev \
    && rm -rf /var/cache/apk/*

COPY . /src
WORKDIR /src
RUN ./configure && make V=s use_fsanitize=no && make install-nonroot

FROM alpine:latest
WORKDIR /root/
COPY --from=0 /usr/local /usr/local
RUN apk update && \
    apk add --no-cache libstdc++ \
    && rm -rf /var/cache/apk/*
RUN addgroup mercury -S && adduser mercury -G mercury -S && \
    chown -R mercury:mercury /usr/local/share/mercury /usr/local/var/mercury/

ENTRYPOINT ["/usr/local/bin/mercury", "-u", "mercury", "-c", "eth0"]
