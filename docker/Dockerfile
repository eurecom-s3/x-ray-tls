ARG BASE_IMAGE=ubuntu:20.04

FROM $BASE_IMAGE

# ARG must be after FROM
ARG BCC_VERSION=v0.26.0
ARG WIRESHARK_COMMIT=234f45d8e5e25918a2f517a79c5819949aa40da9

# Multi host OS support
RUN . /etc/os-release; \
    if [ "$ID" = "ubuntu" ] && [ "$VERSION_ID" = "20.04" ]; then \
        apt-get update && \
        DEBIAN_FRONTEND=noninteractive apt-get install -y \
        build-essential cmake linux-headers-$(uname -r) \
        bison build-essential cmake flex git libedit-dev \
        libllvm12 llvm-12-dev libclang-12-dev python zlib1g-dev libelf-dev libfl-dev python3-distutils \
        python3-pip \
        curl libglib2.0-dev libgcrypt-dev libc-ares-dev gnutls-dev libpcap-dev && \
        rm -rf /var/lib/apt/lists/*; \
    elif [ "$ID" = "debian" ] && [ "$VERSION_ID" = "11" ]; then \ 
        echo "TODO: debian 11 support" && exit 1; \
    elif [ "$ID" = "arch" ]; then \ 
        echo "TODO: archlinux support" && exit 1; \
    else \
        echo "Unsupported base OS '$BASE_IMAGE'" && \
        exit 1; \
    fi

# Build a modified version of tshark
# GNUTLS-dev must be installed (compilation will be ok but no TLS dissector!)
COPY patchs/tshark.patch /tmp
RUN \
    cd /tmp && \
    curl -o wireshark.tar.bz2 https://gitlab.com/wireshark/wireshark/-/archive/${WIRESHARK_COMMIT}/wireshark-${WIRESHARK_COMMIT}.tar.bz2 && \
    tar -xf wireshark.tar.bz2 && \
    cd wireshark-${WIRESHARK_COMMIT} && \
    git apply /tmp/tshark.patch && \
    mkdir build && \
    cd build && \
    cmake \
        -DCMAKE_INSTALL_PREFIX=/opt/wireshark-custom \
        -DBUILD_wireshark=OFF \
        -DBUILD_tshark=ON \
        -DBUILD_dumpcap=ON \
        -DBUILD_editcap=ON \
        -DBUILD_mergecap=ON \
        -DENABLE_PCAP=ON \
        -DENABLE_GNUTLS=ON .. && \
    make -j$(nproc) && \
    make install && \
    find /opt/wireshark-custom/ -type d -exec chmod 755 {} \; && \
    find /opt/wireshark-custom/ -type f -exec chmod 644 {} \; && \
    find /opt/wireshark-custom/bin/ -type f -exec chmod 755 {} \; && \
    cd /tmp && \
    rm -rf /tmp/wireshark wireshark.tar.bz2 /tmp/tshark.patch && \
    /opt/wireshark-custom/bin/tshark --version | grep -q "GnuTLS" || { echo "tshark was not compiled with GnuTLS"; exit 1; } && \
    /opt/wireshark-custom/bin/tshark --version | grep -q "libpcap" || { echo "tshark was not compiled with libpcap"; exit 1; }

# Install BCC
RUN \
    cd /tmp && \
    git clone --depth 1 --branch $BCC_VERSION https://github.com/iovisor/bcc.git && \
    mkdir bcc/build && \
    cd bcc/build && \
    cmake .. && \
    make -j$(nproc) && \
    make install && \
    cmake -DPYTHON_CMD=python3 .. && \
    cd src/python/ && \
    make && \
    make install && \
    cd /tmp && \
    rm -rf /tmp/bcc

# Install Python dependencies
COPY requirements.txt /opt
RUN pip3 install -r /opt/requirements.txt

# Add /opt/wireshark-custom/bin/ to PATH
ENV PATH /opt/wireshark-custom/bin:$PATH

# Copy and compile (Cython) code
ENV PYTHONPATH /app
WORKDIR /app

COPY setup.py /app
COPY src /app/src

RUN python3 setup.py build_ext --inplace -j$(nproc)

ENTRYPOINT [ "python3", "-u", "src/main.py" ]
