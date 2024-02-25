FROM debian:11

SHELL ["/bin/bash", "-c"]

# Create user
RUN groupadd -g 1001 tlsuser && \
    useradd -s /bin/bash -u 1001 -g 1001 -m tlsuser

# Install packages
RUN \
    apt-get update && \
    apt-get install -y \
    build-essential \
    git curl wget python3 python3-pip openssl

COPY scripts /home/tlsuser/scripts
RUN \
    chown -R tlsuser /home/tlsuser/scripts && \
    chmod 755 /home/tlsuser/scripts/*

USER tlsuser

# Install Python packages
RUN pip3 install --user requests

WORKDIR /home/tlsuser

ENTRYPOINT [ "/bin/bash" ]
CMD [ "-c", "trap exit SIGTERM; sleep infinity & wait $!" ]
