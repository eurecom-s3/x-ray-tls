#!/bin/bash

set -x

for i in {1..5}
do
    BENCHMARK_RESULTS_FILE=benchmark/results/curl.json bash benchmark/benchmark.sh curl
    sleep 5
    BENCHMARK_RESULTS_FILE=benchmark/results/apps.json bash benchmark/benchmark.sh apps
    sleep 5
done
