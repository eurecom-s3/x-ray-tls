#!/bin/bash

set -x

if [ "$1" != "curl" ] && [ "$1" != "apps" ] && [ "$1" != "selenium" ]; then
    echo "Usage: ./$0 <curl|apps|selenium> [test_file.py::test_name]"
    echo "e.g., ./$0 curl test_curl.py::test_curl_3_sessions"
    exit 2
fi

find $(pwd)/benchmark/dumps \( -type f -name '*.json' -or -name '*.pcap' \) -exec rm -f {} \;
echo "$(pwd)/benchmark/dumps cleared"

# Clean previous containers, if any
docker stop tls-traffic-analyzer || true
docker stop my-tls-clients || true

# Build benchmark image
if [ "$1" == "curl" ]; then
    IMAGE="tls-traffic-analyzer-benchmark-curl:latest"
    docker build -t $IMAGE -f benchmark/docker/curl.Dockerfile benchmark/ || exit 1
elif [ "$1" == "apps" ]; then
    IMAGE="tls-traffic-analyzer-benchmark-apps:latest"
    docker build -t $IMAGE -f benchmark/docker/apps.Dockerfile benchmark/ || exit 1
elif [ "$1" == "selenium" ]; then
    echo "Pulling Selenium images..."
    docker pull selenium/standalone-firefox:latest
fi

# Build tls traffic analyzer image
# TODO: detect if BCC was compiled against a different version of the kernel and if yes add --no-cache
docker build -t tls-traffic-analyzer:latest -f docker/Dockerfile .  || exit 2

if [ "$1" == "curl" ] || [ "$1" == "apps" ]; then
    # Start TLS traffic analyzer
    docker run -it -d --rm \
        --name tls-traffic-analyzer \
        --privileged  \
        -v $(pwd)/benchmark/dumps:/dumps \
        -v /var/run/docker.sock:/var/run/docker.sock \
        -e ENABLE_BASELINE=false \
        -e STATUS_FILE=/tmp/status \
        --network host --pid host \
        tls-traffic-analyzer:latest \
        -o /dumps --chown-traffic-dumps $UID \
        --container my-tls-clients -vv
    echo "TLS analyzer started"

    # Start TLS clients container
    docker run -it -d --rm --name my-tls-clients $IMAGE

    echo "Waiting for TLS traffic analyzer to start..."
    sleep 10
fi

# Run tests
# Add -o log_cli_level=DEBUG for debug logs
JSON_REPORT_ARGS="--json-report --json-report-file benchmark/results/pytest_reports/$(date +%s).json"
if [ -z "$2" ]; then
    # All tests
    pytest -s -o log_cli=true $JSON_REPORT_ARGS -vv benchmark/tests/$1
else
    # Test file / specific tests given as arg
    pytest -s -o log_cli=true $JSON_REPORT_ARGS -vv benchmark/tests/$1/$2
fi
pytest_exit_code=$?

if [ "$1" == "curl" ] || [ "$1" == "apps" ]; then
    if [ $pytest_exit_code -eq 0 ]; then
        docker stop tls-traffic-analyzer
        docker stop my-tls-clients
        echo "Containers stopped and removed"
    else
        echo "Containers were not removed to allow debugging"
    fi
fi

exit $pytest_exit_code
