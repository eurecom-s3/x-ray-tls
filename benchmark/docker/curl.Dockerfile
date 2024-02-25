FROM debian:11

SHELL ["/bin/bash", "-c"]

# Versions
ARG CURL_VERSION=curl-7_86_0
ARG OPENSSL_VERSION=OpenSSL_1_1_1q
ARG GNUTLS_VERSION=3.7.2
ARG WOLFSSL_VERSION=v5.5.3-stable
ARG MBEDTLS_VERSION=v3.2.1
ARG BEARSSL_VERSION=0.6
ARG NGHTTP3_VERSION=v0.7.1
ARG NGTCP2_VERSION=v0.11.0

# Install packages and setup git
RUN \
    apt-get update && \
    apt-get install --no-install-recommends -y \
    build-essential git ca-certificates autoconf perl gcc make libc6-dev libtool strace \
    gettext autopoint libev-dev \
    automake autogen nettle-dev libp11-kit-dev libtspi-dev libunistring-dev \
    guile-2.2-dev libtasn1-6-dev libidn2-0-dev gawk gperf \
    python3-pip python3-jinja2 curl \
    libunbound-dev dns-root-data bison wget patch && \
    rm -rf /var/lib/apt/lists/* && \
    git config --global advice.detachedHead false

# curl can use a lot of different TLS libs
# BearSSL: --with-bearssl
# GnuTLS: --with-gnutls.
# mbedTLS: --with-mbedtls
# NSS: --with-nss
# OpenSSL: --with-openssl (also for BoringSSL and libressl)
# wolfSSL: --with-wolfssl

###
# Download curl source
###
WORKDIR /tmp
RUN git clone --branch $CURL_VERSION --depth 1 https://github.com/curl/curl.git /tmp/curl

###
# curl with OpenSSL
###
RUN \
    git clone --branch $OPENSSL_VERSION --depth 1 https://github.com/openssl/openssl.git openssl/ && \
    cd openssl/ && \
    ./config --prefix=/opt/openssl && \
    make -j$(nproc) && \
    make install && \
    cd .. && \
    rm -rf openssl/
RUN \
    cp -r curl curl-openssl && \
    cd curl-openssl && \
    autoreconf -fi && \
    ./configure --prefix=/opt/curl-openssl --with-openssl=/opt/openssl && \
    make -j$(nproc) && \
    make install && \
    cd /tmp && \
    rm -rf /tmp/curl-openssl

###
# curl with GnuTLS
###
RUN \
    git clone --branch $GNUTLS_VERSION --depth 1 https://gitlab.com/gnutls/gnutls.git gnutls/ && \
    cd gnutls/ && \
    ./bootstrap && \
    ./configure --prefix=/opt/gnutls --disable-doc --disable-manpages && \
    make -j$(nproc) && \
    make install && \
    cd .. && \
    rm -rf gnutls/
RUN \
    cp -r curl curl-gnutls && \
    cd curl-gnutls && \
    autoreconf -fi && \
    ./configure --prefix=/opt/curl-gnutls --with-gnutls=/opt/gnutls && \
    make && \
    make install && \
    cd /tmp && \
    rm -rf /tmp/curl-gnutls

###
# curl with GnuTLS (QUIC)
###
# ngtcp2 (QUIC support)
RUN \
    git clone --branch $NGHTTP3_VERSION --depth 1 https://github.com/ngtcp2/nghttp3 nghttp3/ && \
    cd nghttp3 && \
    autoreconf -fi && \
    ./configure --prefix=/opt/nghttp3 --enable-lib-only && \
    make -j$(nproc) && \
    make install && \
    cd .. && \
    rm -rf nghttp3/
# PKG_CONFIG_PATH should refer to GnuTLS libs and ngtcp2 libs
RUN \
    git clone --branch $NGTCP2_VERSION --depth 1 https://github.com/ngtcp2/ngtcp2 ngtcp2/ && \
    cd ngtcp2 && \
    autoreconf -fi && \
    ./configure PKG_CONFIG_PATH=/opt/gnutls/lib/pkgconfig:/opt/nghttp3/lib/pkgconfig LDFLAGS="-Wl,-rpath,/opt/gnutls/lib" --prefix=/opt/ngtcp2 --enable-lib-only --with-gnutls && \
    make -j$(nproc) && \
    make install && \
    cd .. && \
    rm -rf ngtcp2/
RUN \
    cp -r curl curl-gnutls-http3 && \
    cd curl-gnutls-http3 && \
    autoreconf -fi && \
    ./configure --prefix=/opt/curl-gnutls-http3 --with-gnutls=/opt/gnutls --with-nghttp3=/opt/nghttp3 --with-ngtcp2=/opt/ngtcp2 && \
    make && \
    make install && \
    cd /tmp && \
    rm -rf /tmp/curl-gnutls-http3

###
# curl with WolfSSL
###
RUN \
    git clone --branch $WOLFSSL_VERSION --depth 1 https://github.com/wolfSSL/wolfssl.git wolfssl/ && \
    cd wolfssl/ && \
    ./autogen.sh && \
    ./configure --prefix=/opt/wolfssl --enable-tls13 --enable-curl && \
    make -j$(nproc) && \
    make install && \
    cd .. && \
    rm -rf wolfssl/
RUN \
    cp -r curl curl-wolfssl && \
    cd curl-wolfssl && \
    autoreconf -fi && \
    ./configure --prefix=/opt/curl-wolfssl --with-wolfssl=/opt/wolfssl && \
    make && \
    make install && \
    cd /tmp && \
    rm -rf /tmp/curl-wolfssl

###
# curl with mBedTLS
###
RUN \
    git clone --branch $MBEDTLS_VERSION --depth 1 https://github.com/Mbed-TLS/mbedtls mbedtls/ && \
    cd mbedtls/ && \
    make -j$(nproc) && \
    make DESTDIR=/opt/mbedtls install && \
    cd .. && \
    rm -rf mbedtls/
RUN \
    cp -r curl curl-mbedtls && \
    cd curl-mbedtls && \
    autoreconf -fi && \
    ./configure --prefix=/opt/curl-mbedtls --with-mbedtls=/opt/mbedtls && \
    make && \
    make install && \
    cd /tmp && \
    rm -rf /tmp/curl-mbedtls

###
# curl with NSS
# NSS use must be confirmed using --with-nss-deprecated.
# NSS support will be dropped from curl in August 2022.
# See docs/DEPRECATE.md
###
RUN apt-get update && apt-get install -y libnss3-dev libcurl4-nss-dev && rm -rf /var/lib/apt/lists/*
RUN \
    cp -r curl curl-nss && \
    cd curl-nss && \
    autoreconf -fi && \
    ./configure --prefix=/opt/curl-nss --with-nss --with-nss-deprecated && \
    make && \
    make install && \
    cd /tmp && \
    rm -rf /tmp/curl-nss

###
# curl with BearSSL
###
RUN \
    curl -f -o bearssl.tar.gz https://bearssl.org/bearssl-$BEARSSL_VERSION.tar.gz && \
    tar -xf bearssl.tar.gz && \
    cd bearssl-$BEARSSL_VERSION/ && \
    make -j$(nproc) && \
    mkdir -p /opt/bearssl/lib /opt/bearssl/include && \
    cp build/libbearssl.* /opt/bearssl/lib && \
    cp inc/*.h /opt/bearssl/include && \
    cd .. && \
    rm -rf bearssl-$BEARSSL_VERSION/ bearssl.tar.gz
RUN \
    cp -r curl curl-bearssl && \
    cd curl-bearssl && \
    autoreconf -fi && \
    ./configure --prefix=/opt/curl-bearssl LDFLAGS="-Wl,-rpath,/opt/bearssl/lib" --with-bearssl=/opt/bearssl && \
    make && \
    make install && \
    cd /tmp && \
    rm -rf /tmp/curl-bearssl


USER nobody

WORKDIR /opt

ENTRYPOINT [ "/bin/bash" ]
CMD [ "-c", "trap exit SIGTERM; sleep infinity & wait $!" ]
