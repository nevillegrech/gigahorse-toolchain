# EVM Decompiler (Bytecode Disassembly -> Three-Address Code)

This project contains the source code for our Ethereum VM bytecode disassembly
decompiler. It takes output from disasm, the Ethereum bytecode dissassembler,
as input, and outputs a three-address code representation.

## Development Environment

An installation of **Python 3.5** or later is required, alongside various
packages. The recommended way to install all package dependencies is using
`pip` and our provided `requirements.txt`, like so:

```
$ pip install -r requirements.txt
```

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

## Git / Trello Development Workflow

Most development should happen on *feature branches*. Here's our git workflow:

1. To work on a new feature, create a new **git** branch based on the latest
   master commit, with a sensible name (e.g. `three_address`). Move the feature's
   corresponding **Trello** card(s) to *In Progress*.
2. Commit to the new feature branch early and often.
3. When the feature is complete, submit a **Bitbucket pull request** to merge
   the feature branch into our master branch. Move the corresponding **Trello**
   card to *Code Review*.
4. Someone else will review the pull request:
    - If changes are needed, the reviewer will comment with necessary changes
      and move the **Trello** card back to *In Progress*. Continue committing to
      the feature branch - the pull request will be updated automatically.
    - Otherwise, if no changes are needed, the reviewer will **merge** the pull
      request and move the **Trello** card to *Complete*.

Please ensure the pull request does not indicate  merge conflicts with the
`master` branch. If it does, manually resolve these conflicts by merging
`master` ***into* the feature branch**.

If any code needs to be explainer to a reviewer, then it probably needs
comments with the explanation.

## Unit Testing

Our testing framework is [pytest](http://doc.pytest.org/). Tests can be run
from the repository root or the `test/` subdirectory like so (or with the `-v`
flag for more detail on each test):

```
$ pytest
```

All modules should be comprehensively unit-tested, with tests placed in a file
called `test/test_MODULE.py`, where MODULE is the name of the corresponding
Python module from `src/`.

Test fixtures and `pytest` settings are defined in `test/conftest.py`.
