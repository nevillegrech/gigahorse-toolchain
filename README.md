### The Gigahorse decompiler and toolchain


## Installation:

Requires a modern Python 3 distribution, e.g. the Anaconda Python distribution: https://anaconda.org/anaconda/python

Requires Souffle: http://souffle-lang.org/

Requires PyDot:
```
conda install -c anaconda pydot
```

Requires Graphviz

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


