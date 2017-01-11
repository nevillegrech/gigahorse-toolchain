# Bulk analyser

`analyse.py` is used to run the cfg analysis on many contracts at a time.

The program expects to find a collection of contract bytecode files in some
specified directory, and it will run the analysis on each one and categorise it
according to whether it fully resolves all edges in its CFG or not.

The expected file format for each contract is as the scraper produces,
which is to say that by default it will examine any file in the specified folder
ending in "runtime.hex".

Contracts that take too long to analyse will be skipped after a configurable
timeout.

Results are placed in a `results/` directory; it places one filename per line
in several files, each file being the collection of all contracts in a given
category.

`analyse.py --help` for invocation instructions.
