# Bulk analyser

`analyse.py` is used to run an analysis on many contracts at a time.

The program requires [souffle](https://github.com/souffle-lang/souffle) to be installed,
and a datalog specification of the properties placed in `spec.dl` by default.
The analyser expects to find a collection of contract bytecode files in some
specified directory, and it will run the analysis given in `spec.dl` on each one.

The expected file format for each contract is as the scraper produces,
which is to say that by default it will examine any file in the specified folder
ending in "runtime.hex".

Contracts that take too long to analyse will be skipped after a configurable
timeout.

Results are placed in a `results.json` file, as a list of triples in the form:

```[filename, properties, flags]```

Here, `properties` is a list of the detected issues with the contract in filename,
where any output relations in `spec.dl` that are non-empty will have their relation
name placed in this list.
`flags` is a list indicating auxiliary or exceptional information. It may include
`"ERROR"` and `"TIMEOUT"`, which are self-explanatory, and also `"UNRESOLVED"`,
which indicates that the decompiler was not able to resolve all jumps in the
graph of a given contract.

`analyse.py --help` for invocation instructions.
