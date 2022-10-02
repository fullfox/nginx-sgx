# Load injection
Load injection use **k6**.
Test parameters are defined at the beginning of the ``constant-arrival-rate.js`` file.

A test can be run with ``k6 run constant-arrival-rate.js``.

With data logging in JSON file format, run ``k6 run constant-arrival-rate.js --out json=log_file.json``.

## Plotting
Generated JSON files can be parsed and plotted using ``./parser.py [json_file]``.
