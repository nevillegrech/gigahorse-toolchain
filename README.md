# Using this repo

To pull new hotness from the public repo:

cd private-repo
git remote add public https://github.com/exampleuser/public-repo.git
git pull public master # Creates a merge commit
git push origin master
Awesome, your private repo now has the latest code from the public repo plus your changes.

Finally, to create a pull request private repo -> public repo:

The only way to create a pull request is to have push access to the public repo. This is because you need to push to a branch there (here's why).

git clone https://github.com/exampleuser/public-repo.git
cd public-repo
git remote add private_repo_yourname https://github.com/yourname/private-repo.git
git checkout -b pull_request_yourname
git pull private_repo_yourname master
git push origin pull_request_yourname
Now simply create a pull request via the Github UI for public-repo, as described here.

# Vandal

Vandal is a static program analysis framework for Ethereum smart contract
bytecode. It decompiles EVM bytecode or disassembly to an
equivalent intermediate representation, including the contract's control
flow graph. This representation removes all stack operations and
thereby exposes data dependencies which are otherwise obscured.
This information is then fed, with a Datalog specification, into an analysis
engine for the extraction of program properties.

Vandal provides a platform for detecting potential security vulnerabilities
in compiled contract bytecode, and supports rapid development of prototyping
of new vulnerability specifications written in Datalog.
In a similar fashion, smart contract logic can be more conveniently inspected
and analysed in other areas, such as correctness and efficiency.

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

Sphinx is used for code documentation generation. Sphinx source files are in
`doc/source/`. To build clean HTML documentation, run:

```
$ make clean doc
```

from the repository root. The documentation index will be placed at
`doc/build/html/index.html`.


## Code Style

- Use four spaces for indentation
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

Most development should happen on *feature branches* in personal forks. Here's
our git workflow:

1. Fork our repository to your own account, and create a new git branch for
   your feature.
2. Commit to the feature branch early and often.
3. When the feature is complete, submit a **pull request** to merge your fork's
   feature branch into our repository's master branch.
4. A project member will review the pull request:
    - If changes are needed, the reviewer will comment with necessary changes
      Continue committing to the feature branch - the pull request will be
      updated automatically.
    - Otherwise, if no changes are needed, the reviewer will approve the pull
      request for merging.
    - Note: all Travis-CI status checks are required to pass before a PR is
      merged, and the feature branch must be up to date with master.

If any code needs to be explained to a reviewer, then it probably needs
more comments containing the explanation or may need re-factoring.

## Unit Testing

Our testing framework is [pytest](http://doc.pytest.org/). Tests can be run
from the repository root or the `test/` sub-directory like so (or with the `-v`
flag for more detail on each test):

```
$ pytest
```

Alternatively, you can also use the `Makefile` in the repository root like so:

```
$ make test
```

The goal is for all modules to be comprehensively unit-tested, with tests
placed in a file called `test/test_MODULE.py`, where MODULE is the name of the
corresponding Python module from `src/`.

Test fixtures and `pytest` settings are defined in `test/conftest.py`.
