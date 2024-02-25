# T_stop estimation

We experiment the variation of T_stop with respect to system load average.
As described in the paper, T_stop should stay below network RTT.

## Requirements

- BCC
- Python
- Jupyter Notebook

## Run the experiment

Run in parallel:

- Save time to stop target process and load average in a CSV file:
```sh
$ sudo PYTHONPATH=. python3 tools/T_stop_estimation/measure_T_stop.py <interface>
```

- Increase load average on regular basis:
```sh
$ for exp in {1..5}; do for cpu in {1..8}; do stress --cpu $cpu --timeout 60; done; sleep 180; done
```

Experiment will take 55 minutes.

Results will be owned by root. Change owner to current user:
```sh
$ sudo chown $USER tools/T_stop_estimation/results.csv
```

Then open `Explore T_dump measures.ipynb` with Jupyter Notebook to explore results.
