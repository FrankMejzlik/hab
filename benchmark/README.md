# HAB benchmarking

This is a helper binary that generates the benchmarking results for HAB library --- e.g. empiric times to re-authenticate after missing a specific number of messages for the given configuration. Due to performance reasons, this benchmarks do not use the actual implementations but the simulated version; these do the identical thing in regards to authentication and identity management but without the network and signature overhead.

## Benchmarked key ratios

The three basic types of key ratios. Also, list of the same ratios can be considered, but the results are not particularly interesting since the time to reauthenticate would be always one message but for a price of huge overhead.

```sh
# Exponential
[1024, 256, 64, 16, 4, 1];
# Linear
[1354, 1083, 812, 542, 271, 1]
# Logarithmic
[1360, 1357, 1344, 1286, 1040, 1]
```

To generate TSV outputs for ggplot, run this:

```sh
Rscript plots/plot-re-auth-time.R
```

You will find the plots inside the `plots/out/` directory.
