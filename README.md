# EVM Decompiler (Bytecode Disassembly -> Three-Address Code)

This project contains the source code for our Ethereum VM bytecode disassembly decompiler. It takes output from disasm, the Ethereum bytecode dissassembler, as input, and outputs a three-address code representation.

## Requirements

* Python 3.5+ 
* networkx and pygraphviz for drawing graphs

## Code Style

- Use two spaces for indentation
- Every public method and class must have a Python docstring
- Every public method/function definition should have Python 3 [type hints](https://docs.python.org/3/library/typing.html)
- Don't pollute the global scope
- Don't override Python 3 reserved words or built-ins
- Keep line lengths to a maximum of 79 characters
- Do not leave trailing whitespace at the end of a line
- Avoid `from _ import *` wherever possible
- Use meaningful variable names. Single letters are OK ***iff*** the meaning is clear and unambiguous, e.g. `for l in lines` where `l` could have no other meaning
- Use inline comments to explain complicated sections of code

## Git / Trello Development Workflow

Most development should happen on *feature branches*. Here's our git workflow:

1. To work on a new feature, create a new **git** branch based on the latest master commit, with a sensible name (e.g. `three_address`). Move the feature's corresponding **Trello** card(s) to *In Progress*.
2. Commit to your new feature branch early and often.
3. When the feature is complete, submit a **Bitbucket pull request** to merge your feature branch into the master branch. Move the corresponding **Trello** card to *Code Review*.
4. Someone else will review the pull request:
    - If changes are needed, the reviewer will comment with necessary changes and move the **Trello** card back to *In Progress*. Continue committing to your feature branch - the pull request will be updated automatically.
    - Otherwise, if no changes are needed, the reviewer will **merge** the pull request and move your **Trello** card to *Complete*. 
    
You should ensure your pull request does not contain merge conflicts with the `master` branch. If it does, you need to manually resolve these conflicts by merging `master` ***into* your feature branch**.

If you need to explain any code to a reviewer then it probably needs comments with the explanation.