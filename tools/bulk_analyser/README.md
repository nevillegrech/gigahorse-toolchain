# Bulk analyser

`analyse.py` is used to run the cfg analysis on many contracts at a time.

The expected file format for each contract is as the scraper produces,
which is to say it will examine any file in the specified folder ending in
"runtime.hex".

Contracts that take too long to analyse will be skipped after a configurable
timeout.

Results are placed in a `results/` directory; it places one filename per line
in several files, each file being the collection of all contracts in a given
category.
