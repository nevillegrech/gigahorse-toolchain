[Gigahorse](https://vignette.wikia.nocookie.net/roadwarrior/images/e/ea/MMFR_Gigahorse-876x534.jpg/revision/latest?cb=20150427175606)
=============================

Note: you need to clone this repo using the `--recursive` flag since this repo has submodules, e.g., `git clone git@github.com:nevillegrech/gigahorse-toolchain.git --recursive`


# The Gigahorse decompiler and toolchain [![Tweet](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?text=Gigahorse%20-%20Decompilation%20and%20Analysis%20for%20Ethereum%20Smart%20Contracts&url=https://www.github.com/nevillegrech/gigahorse-toolchain)
A decompiler (and related framework) from low-level EVM code to a higher-level function-based three-address representation, similar to LLVM IR or Jimple. Originally published as:

- Grech, N., Brent, L., Scholz, B., Smaragdakis, Y. (2019), Gigahorse: Thorough, Declarative Decompilation of Smart Contracts. *In 41st ACM/IEEE International Conference on Software Engineering.*

In addition, other research tools have been developed on top of Gigahorse, including:

-  Grech, N., Kong, M., Jurisevic, A., Brent, L., Scholz, B., Smaragdakis, Y. (2018), MadMax: Surviving Out-of-Gas Conditions in Ethereum Smart Contracts. *Proceedings of the ACM on Programming Languages (OOPSLA).*

-  Brent, L., Grech, N., Scholz, B., Smaragdakis, Y. (2020), Ethainter: A Smart Contract Security Analyzer for Composite Vulnerabilities.
*In 41st ACM SIGPLAN Conference on Programming Language Design and Implementation.*

-  Lagouvardos, S., Grech, N., Tsatiris, I., and Smaragdakis, Y. (2020) Precise Static Modelling of Ethereum "Memory". *Proceedings of the ACM in Programming Languages (OOPSLA).*

-  Grech, N., Kong, M., Jurisevic, A., Brent, L., Scholz, B., Smaragdakis, Y. (2020),  Analyzing the Out-of-Gas World of Smart Contracts. *Communications of the ACM.*


The Gigahorse framework also underpins the realtime decompiler and analysis tool at [contract-library.com](https://contract-library.com).



## Installation:

### Python 3.8
Refer to standard documentation.

### Souffle 2.0+
Refer to Souffle documentation. The easiest way to install this is to use the precompiled images from https://github.com/souffle-lang/souffle/releases

### Souffle custom functors
Navigate to the `souffle-addon` folder
```
cd souffle-addon
```

Build:
```
make
```

Move compiled object files to `gigahorse-toolchain` folder
```
mv *.so ..
```


### For visualization (optional)
Requires PyDot:
```
pip install pydot
```

Requires Graphviz

Installation on Debian:
```
sudo apt install graphviz
```

## Usage
1. Fact generation
2. Run decompiler using Souffle
3. Visualize results


```
./generatefacts <contract> facts
souffle -F facts logic/decompiler.dl
./visualizeout.py
```

For batch processing of contracts, we recommend the bulk analyzer script:  `bulk_analyze.py`.


## Writing client analyses

In order to write client analyses for decompiled bytecode, we recommend that you create a souffle logic file that includes `clientlib/decompiler_imports.dl`, for instance:
```
#include "clientlib/decompiler_imports.dl"

.output ...
```
