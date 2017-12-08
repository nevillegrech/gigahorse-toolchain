# Vandal: An EVM bytecode decompiler

This project contains the source code for our Ethereum VM bytecode decompiler,
`vandal`.
It takes EVM bytecode or disassembly as input, and outputs an equivalent
intermediate representation, including the program's control flow graph.
This intermediate representation removes all stack operations and, in concert
with the CFG, exposes data dependencies. The aim of this project is to allow
compiled smart contract logic to be inspected more conveniently,
either by hand or by machine.


## Requirements

An installation of **Python 3.5** or later is required, alongside various
packages. The recommended way to install all package dependencies is using
`pip` and our provided `requirements.txt`, like so:

```
$ pip install -r requirements.txt
```


## Usage

The decompiler and disassembler are invoked at their simplest as follows:

```
$ bin/decompile examples/dao_hack.hex
$ bin/disassemble -p examples/dao_hack.hex
```

Some cursory information can be obtained by producing verbose debug output:

```
$ bin/decompile -n -v examples/dao_hack.hex
```

For manual inspection of a contract, html graph output can be handy:

```
$ bin/decompile -n -v -g graph.html examples/dao_hack.hex
```

This produces an interactive page, `graph.html`. If clicked, each node on this
page displays the code in the basic block it represents, an equivalent
decompiled block of code, and some accompanying information.


Further invocation options are detailed when the `--help` flag is supplied:

```
$ bin/decompile --help
$ bin/disassemble --help
```

### Configuration

Configuration options can be set in `bin/config.ini`. A default value and brief
description of each option is provided in `src/default_config.ini`. Any of
these settings may be overridden with the `-c` flag in a `"key=value"` fashion.

### Example

A contract, `loop.sol`:
```javascript
contract TestLoop {
    function test() returns (uint) {
        uint x = 0;
        for (uint i = 0; i < 256; i++) {
            x = x*i + x;
        }
        return x;
    }
}
```

Compiled into runtime code, held in `loop.hex`, then decompiled
and output into an html file:
```
$ solc --bin-runtime loop.sol | tail -n 1 > loop.hex
$ bin/decompile -n -v -c "remove_unreachable=1" -g loop.html loop.hex
```


## Documentation

Sphinx is used for documentation generation with documentation source files in
`doc/source/`. To build clean HTML documentation, run:

```
$ make clean doc
```

from the repository root. The documentation index will be placed at
`doc/build/html/index.html`.

There are also some notes on the github wiki.


## Code Style

- Use two spaces for indentation
- Every public method and class must have a Python docstring
- Every public method/function definition should have Python 3
  [type hints](https://docs.python.org/3/library/typing.html)
- Don't pollute the global scope
- Don't override Python 3 reserved words or built-ins
- Keep line lengths to a maximum of 79 characters
- Do not leave trailing whitespace at the end of a line
- Avoid `from _ import *` wherever possible
- Use meaningful variable names. Single letters are OK ***iff*** the meaning is
  clear and unambiguous, e.g. `for l in lines` where `l` could have no other
  meaning
- Use inline comments to explain complicated sections of code
- Use consistent variable naming across modules to avoid confusion
- When building on an existing `class`, favour inheritance over wrapping
- Use classes whenever practical

## Development Workflow

Most development should happen on *feature branches*. Here's our git workflow:

1. To work on a new feature, create a new **git** branch based on the latest
   master commit, with a sensible name. Move the feature's corresponding
   project card(s) to *In Progress*.
2. Commit to the new feature branch early and often.
3. When the feature is complete, submit a **pull request** to merge
   the feature branch into our master branch. Move the corresponding project
   card to *Code Review*.
4. Someone else will review the pull request:
    - If changes are needed, the reviewer will comment with necessary changes
      and move the project card back to *In Progress*. Continue committing to
      the feature branch - the pull request will be updated automatically.
    - Otherwise, if no changes are needed, the reviewer will **merge** the pull
      request and move the project card to *Complete*.

Please ensure the pull request does not indicate merge conflicts with the
`master` branch. If it does, manually resolve these conflicts by merging
`master` into the feature branch.

If any code needs to be explainer to a reviewer, then it probably needs
comments with the explanation.

## Unit Testing

Our testing framework is [pytest](http://doc.pytest.org/). Tests can be run
from the repository root or the `test/` subdirectory like so (or with the `-v`
flag for more detail on each test):

```
$ pytest
```

Alternatively, you can also use the `Makefile` in the repository root like so:

```
$ make test
```

All modules should be comprehensively unit-tested, with tests placed in a file
called `test/test_MODULE.py`, where MODULE is the name of the corresponding
Python module from `src/`.

Test fixtures and `pytest` settings are defined in `test/conftest.py`.
