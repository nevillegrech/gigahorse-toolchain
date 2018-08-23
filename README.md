![Gigahorse](https://vignette.wikia.nocookie.net/roadwarrior/images/e/ea/MMFR_Gigahorse-876x534.jpg/revision/latest?cb=20150427175606)
=============================
# The Gigahorse decompiler and toolchain [![Tweet](https://img.shields.io/twitter/url/http/shields.io.svg?style=social)](https://twitter.com/intent/tweet?text=Gigahorse%20-%20Decompilation%20and%20Analysis%20for%20Ethereum%20Smart%20Contracts&url=https://www.github.com/nevillegrech/gigahorse-toolchain)
A decompiler from low level EVM code to a higher level functional three address representation similar to LLVM IR or Jimple, and framework.


## Installation:

Requires a modern Python 3 distribution, e.g. the Anaconda Python distribution: https://anaconda.org/anaconda/python

Requires Souffle: http://souffle-lang.org/

### For visualization
Requires PyDot:
```
conda install -c anaconda pydot
```
Requires Graphviz

Installation on Debian:
```
sudo apt install graphviz
```

### For public function signature matching
run `bin/crawlsignatures` (optional)

## Usage
1. Fact generation
2. Run decompiler using Souffle
3. Visualize results


```
cd logic
../bin/generatefacts -i <contract> facts
souffle -F facts decompiler.dl
./visualizeout.py
```

For batch processing of contracts, we recommend the bulk analyzer script in `logic/analyze.py`.


## Writing client analyses

In order to write client analyses for decompiled bytecode, we recommend that you create a souffle logic file that includes `clientlib/decompiler_imports.dl`, for instance:
```
#include "clientlib/decompiler_imports.dl"

.output ...
```
