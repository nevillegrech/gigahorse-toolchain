*NOTE*: you need to clone this repo using the `--recursive` flag since this repo has submodules, e.g., `git clone git@github.com:nevillegrech/gigahorse-toolchain.git --recursive`

# The Gigahorse binary lifter and toolchain [![Tweet](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?text=Gigahorse%20-%20Decompilation%20and%20Analysis%20for%20Ethereum%20Smart%20Contracts&url=https://www.github.com/nevillegrech/gigahorse-toolchain)
A binary lifter (and related framework) from low-level EVM code to a higher-level function-based three-address representation, similar to LLVM IR or Jimple. 

## Quickstart

### Running/Installing Gigahorse from local clone (requires `souffle`)
Our dependencies installation [Dockerfile](docker/dependencies/souffle24/Dockerfile) can be used as a reference for installing the dependencies of Gigahorse on a debian-based system. The Dockerfile also includes the instructions to build `souffle` 2.4.1 from source.

In summary, you need to have the following things installed on your system:

- Boost libraries, required for [souffle-addon](https://github.com/plast-lab/souffle-addon) (Can be installed on Debian with `apt install libboost-all-dev`)

- Z3, required for [souffle-addon](https://github.com/plast-lab/souffle-addon) (Can be installed on Debian with `apt install libz3-dev`)

- Python 3.8 (Refer to standard documentation)

- Souffle 2.3 or 2.4.1 (We only test using the release versions, later development versions may work but are untested by us. The easiest way to install this is to use the release from https://github.com/souffle-lang/souffle/releases/tag/2.4.1). Refer to the Souffle [documentation](https://souffle-lang.github.io) for more information.

Now install the Souffle custom functors:

```
# builds all, sets libfunctors.so as a link to libsoufflenum.so
cd souffle-addon && make WORD_SIZE=$(souffle --version | sed -n 3p | cut -c12,13)
```

You should now be ready to run Gigahorse.

### Installing Gigahorse via docker

Alternatively, you can use Gigahorse via our pre-built docker images using the following instructions:
1. For amd64:
   ```
   curl -s -L https://raw.githubusercontent.com/nevillegrech/gigahorse-toolchain/master/scripts/docker/install/install_amd64 | bash
   ```

   For arm64/m1 (not actively tested):
   ```
   curl -s -L https://raw.githubusercontent.com/nevillegrech/gigahorse-toolchain/master/scripts/docker/install/install_arm64 | bash
   ```
2. Then ```source ~/.bashrc```

3. Check if gigahorse is available using ```gigahorse --help```

## Running Gigahorse
The `gigahorse.py` script can be run on a contract individually or on a collection of contract bytecode files in specified directory, and it will run the binary lifter implemented in `logic/main.dl` on each contract, optionally followed by any additional client analyses specified by the user using the `-C` flag.

The default pipeline first attempts to decompile a contract using a **shrinking** context-sensitivity configuration. If that times out it performs a second attempt with the _scalable-fallback_ configuration (using a **finite-precise** context sensitivity algorithm, tuned for scalability). The _scalable-fallback_ configuration can be disabled if needed using the `--disable_scalable_fallback` flag.

The Gigahorse pipeline also includes a few rounds of inlining of small functions in order to help the subsequent client libraries get more high-level inferences. The inlining functionality can be disabled with `--disable_inline`.

The expected file format for each contract is in .hex format.

Example (individual contract):

```
./gigahorse.py examples/long_running.hex
```

(For some Souffle versions, you will get an error message regarding the `libsoufflenum.so` dynamic library, during the first compilation. You can ignore this and gigahorse.py should work upon a re-run.)

Contracts that take too long to analyse will be skipped after a configurable timeout.

The decompilation results are placed in the directory `.temp`, whereas metadata about the execution, e.g., metrics are placed in a `results.json` file, as a list of triples in the form:

```[filename, properties, flags]```

Here, `properties` is a list of the detected issues with the contract in filename,
where any output relations in the datalog files that are non-empty will have their
relation name placed in this list.
`flags` is a list indicating auxiliary or exceptional information. It may include
`"ERROR"` and `"TIMEOUT"`, which are self-explanatory.

`gigahorse.py --help` for invocation instructions.


Example (with client analysis):

 ```
./gigahorse.py  -j <number of jobs> -C clients/visualizeout.py <contracts>
```

(The clients following the `-C` flag can be a comma-separated list, with no spaces, of path-reachable or fully-qualified filenames.)

Gigahorse can also be used in "bulk analysis" mode, by replacing <contracts> by a directory filled with contracts.

For additional instructions in tuning the Gigahorse framework see [Advanced.md](Advanced.md).


## Textual representation of the lifted IR
Client analysis `clients/visualizeout.py` can be used to provide a pretty-printed textual representation of the IR produced by Gigahorse.
The pretty-printed text file is named `contract.tac` and will be placed in the `out/` folder for each analyzed contract.
For example the output for `./gigahorse.py -C clients/visualizeout.py examples/long_running.hex` will be placed in `.temp/long_running/out/contract.tac`.

A block visualized in `contract.tac` looks like:
```
    Begin block 0x3e
    prev=[0xb], succ=[0x10ee, 0x49]
    =================================
    0x3f: v3f(0xf42fdfb) = CONST 
    0x44: v44 = EQ v3f(0xf42fdfb), v32
    0x10c7: v10c7(0x10ee) = CONST 
    0x10c8: JUMPI v10c7(0x10ee), v44
```

Keep in mind that the pretty-printed variable identifiers do not correspond to their identifiers in the underlying datalog facts.


## Writing client analyses

Client analyses can be written in any language by reading the relational files that are written by the decompilation step (`main.dl`). This framework however provides preferential treatment for clients written in Datalog. The most notable example of client analysis for the Gigahorse framework is [MadMax](https://github.com/nevillegrech/MadMax). This uses several of the "analysis client libraries" under [clientlib](https://github.com/nevillegrech/gigahorse-toolchain/tree/master/clientlib). These libraries include [customizable dataflow analysis](clientlib/flows.dl), [memory modeling](clientlib/memory_modeling/README.md), [data structure reconstruction](clientlib/storage_modeling/storage_modeling.dl) and others.

A common template for client analyses for decompiled bytecode is to create souffle datalog file that includes `clientlib/decompiler_imports.dl`, for instance:
```
#include "clientlib/decompiler_imports.dl"

.output ...
```


## Uses of Gigahorse
The Gigahorse toolchain was originally published as:

- Grech, N., Brent, L., Scholz, B., Smaragdakis, Y. (2019), Gigahorse: Thorough, Declarative Decompilation of Smart Contracts. *In 41st ACM/IEEE International Conference on Software Engineering.*

Several novel developments to Gigahorse after the original publication have been published as:

- Grech, N., Lagouvardos, S., Tsatiris, I., Smaragdakis, Y. (2022), Elipmoc: Advanced Decompilation of Ethereum Smart Contracts *Proceedings of the ACM in Programming Languages (OOPSLA).*

The analysis of EVM "memory" operations (`SHA3`, `xCALL`, `LOGx`, etc.) that is [bundled with Gigahorse](clientlib/memory_modeling/README.md) was published as:

-  Lagouvardos, S., Grech, N., Tsatiris, I., Smaragdakis, Y. (2020) Precise Static Modelling of Ethereum "Memory". *Proceedings of the ACM in Programming Languages (OOPSLA).*

In addition, other research tools have been developed on top of Gigahorse, including:

-  Grech, N., Kong, M., Jurisevic, A., Brent, L., Scholz, B., Smaragdakis, Y. (2018), MadMax: Surviving Out-of-Gas Conditions in Ethereum Smart Contracts. *Proceedings of the ACM on Programming Languages (OOPSLA).*

-  Brent, L., Grech, N., Lagouvardos, S., Scholz, B., Smaragdakis, Y. (2020), Ethainter: A Smart Contract Security Analyzer for Composite Vulnerabilities.
*In 41st ACM SIGPLAN Conference on Programming Language Design and Implementation.*

-  Grech, N., Kong, M., Jurisevic, A., Brent, L., Scholz, B., Smaragdakis, Y. (2020),  Analyzing the Out-of-Gas World of Smart Contracts. *Communications of the ACM.*

- Smaragdakis, Y., Grech, N., Lagouvardos, S., Triantafyllou, K., Tsatiris, I. (2021), Symbolic Value-Flow Static Analysis: Deep, Precise, Complete Modeling of Ethereum Smart Contracts. *Proceedings of the ACM in Programming Languages (OOPSLA).*

  



The Gigahorse framework also underpins the realtime decompiler and analysis tool at [app.dedaub.com](https://app.dedaub.com).



