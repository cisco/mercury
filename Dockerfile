FROM alpine:latest
RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/testing/" >> /etc/apk/repositories && \
    apk update && \
    apk add --no-cache build-base git make gcc g++ linux-headers pkgconfig \
    wget tar zlib-dev openssl-dev musl-dev libc-dev \
    && rm -rf /var/cache/apk/*

COPY . /src
WORKDIR /src
RUN ./configure && make V=s && make install-nonroot

FROM alpine:latest
WORKDIR /root/
COPY --from=0 /usr/local /usr/local
RUN apk update && \
    apk add --no-cache libstdc++ \
    && rm -rf /var/cache/apk/*
RUN addgroup mercury -S && adduser mercury -G mercury -S && \
    chown -R mercury:mercury /usr/local/share/mercury /usr/local/var/mercury/
