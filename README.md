# X-Ray-TLS

X-Ray-TLS allows to inspect TLS-encrypted traffic made from local programs by extracting TLS session keys from process memory.

If using this work, please cite [our paper](https://s3.eurecom.fr/docs/asiaccs24_moriconi.pdf):
```bibtex
@inproceedings{moriconi2024xraytls,
  title={X-Ray-TLS: Transparent Decryption of TLS Sessions by Extracting Session Keys from Memory},
  author={Moriconi, Florent and Levillain, Olivier and Francillon, Aurélien and Troncy, Raphael},
  booktitle={Proceedings of the 2024 ACM Asia conference on Computer and Communications Security (ASIACCS)},
  year={2024},
  affiliations = {Eurecom, Samovar, Télécom SudParis, Institut Polytechnique de Paris}
  extralink = {Code: https://github.com/eurecom-s3/x-ray-tls}
}
```

## Getting started

To come soon!

## Method

1. eBPF rules are setup to monitor network traffic
2. On TLS ClientHello, the process initiating the connection is freezed, core dumped and released.
3. When TLS handshake is done, the source process is again freezed, core dumped and released.
4. The TLS session key is extracted from the diff of core dumps.


## Run benchmark

You must have Docker and pytest installed, then run from the root folder:

```sh
bash benchmark/benchmark.sh 
```


## Run with Docker

Running TLS traffic analyzer in docker is supported on the following host OS:
- ubuntu:20.04
- debian:11 (to come soon)
- archlinux:latest (to come soon)
You can use any of the name above in BASE_IMAGE build argument.

```sh
# Build the image with the same base OS as your host OS
# WARNING: you must recompile the image on host kernel updates
# Set BASE_IMAGE=... to one of the supported host OS (see above)
docker build -t tls-traffic-analyzer:latest --no-cache --build-arg BASE_IMAGE=ubuntu:20.04 -f docker/Dockerfile .

# Get interface of default route (or set the interface you want to listen on)
INTERFACE=$(ip -4 route | awk '/default/{print $5}')

# Run without saving traffic dumps for curl commands
# Add -vv for DEBUG
docker run --privileged -it --rm --network host --pid host tls-traffic-analyzer:latest -i $INTERFACE --commands curl

# Run with saving traffic dumps for curl commands
docker run --privileged -it --rm -v $(pwd)/dumps:/dumps --network host --pid host tls-traffic-analyzer:latest -i $INTERFACE -o /dumps --chown-traffic-dumps $UID --commands curl
```


## Run without Docker

Follow instructions in `docker/Dockerfile`.

The program must be run as *root*

```sh
sudo python3 src/main.py
```


## Run traffic analysis on applications running in a Docker container

Applications executed in a Docker container run in a different namespace.
By providing `--container` parameter (container name or id), this tool will bind to the network namespace of the target container (but not other namespaces, like mount namespace).
It means traffic dumps will still be saved on the host filesystem.
In this context, `--interface` parameter should be adapted to match interface name in the docker container, often `eth0`.
Furthermore, if running the tool from a Docker container, you should give access to the host Docker daemon using a bind mount like below:
```sh
docker run --privileged -it --rm -v $(pwd)/dumps:/dumps -v /var/run/docker.sock:/var/run/docker.sock --network host --pid host tls-traffic-analyzer:latest -o /dumps --chown-traffic-dumps $UID --container my_container -vv
```


## Running on all applications on the host system

Doing traffic analysis on all applications running on the host system is not probably not what you want.
Depending on the configuration, this tool may freeze applications for short periods of time and decrypt TLS sessions
that you would not expect to be decrypted and stored on disk.
Therefore, it is strongly encouraged to use `--commands` to limit the analysis to given commands.
If you know what you are doing, running on all commands on the host can be enabled using the environment variable `ALLOW_ALL_COMMANDS_ON_HOST=true`


## Environment variables

- DUMP_METHOD: Set dump method. See paper for details.
Available values: full-full, rst-partial, rst-partial-rst, full-partial, full-partial-rst
- DEBUG_SAVE_DIFF: If set, save memory diff to the path defined (new diff will erase old diff). E.g., DEBUG_SAVE_DIFF=/tmp/diff.bin
- CUSTOM_WIRESHARK_BIN_PATH: Path to custom version of wireshark/tshark.
Default to `/opt/wireshark-custom/bin`. `tshark` and `editcap` binaries are expected.
- STATS_FILENAME: Name of the stats file relative to the dump directory (default to stats.json)
- MEM_REGIONS: Restrict memory dump to regions with paths defined here (separated by comma). Default is to dump all regions with writable flag.
Examples: "[heap]" (heap only), "[heap]," (head and anonymous regions), "[heap],/usr/lib/x86_64-linux-gnu/libnghttp2.so.14.19.0" (heap and a statically assigned memory region).  
To only dump anonymous regions (i.e., dynamically assigned using mmap), use "," (do NOT use "" as it would disable the feature flag).
# (not implemented) - MIN_DIFF_LENGTH_BYTES: If set, only changed parts of the memory larger than MIN_DIFF_LENGTH_BYTES will be added to the memory diff. If not set, all changed parts will be added (with a granularity of 8 bytes).


## Troubleshoot

`sudo python` may refer to python2! Only Python3 is supported.


## Resources
- <https://github.com/iovisor/bcc/blob/master/examples>
- <https://gist.github.com/LeeBrotherston/92cc2637f33468485b8f>
- <https://stackoverflow.com/questions/66825646/scapy-bpf-filter-for-tls-client-hello-and-tcp-syn>
- <https://support.f5.com/csp/article/K10209>
