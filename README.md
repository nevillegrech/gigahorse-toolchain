# EVM Decompiler (Bytecode Disassembly -> Three-Address Code)

This project contains the source code for our Ethereum VM bytecode disassembly decompiler. It takes output from disasm, the Ethereum bytecode dissassembler, as input, and outputs a three-address code representation.

## Code Style

- Use two spaces for indentation
- Every public method and class must have a Python docstring
- Every public method/function definition should have Python 3 [type hints](https://docs.python.org/3/library/typing.html)
- Don't pollute the global scope
- Don't override Python 3 reserved words or built-ins
- Keep line lengths to a maximum of 79 characters
- Do not leave trailing whitespace at the end of a line
- Avoid `from _ import *` wherever possible

## Git/Trello Development Workflow

Most development should happen on *feature branches*. Here's our git workflow:

1. To work on a new feature, create a new **git** branch based on the latest master commit, with a sensible name (e.g. `three_address`). Move the feature's corresponding **Trello** card(s) to *In Progress*.
2. Commit to your new feature branch early and often.
3. When the feature is complete, submit a **Bitbucket pull request** to merge your feature branch into the master branch. Move the corresponding **Trello** card to *Code Review*.
4. Someone else will review the pull request.
  - If changes are needed, the reviewer will comment with necessary changes and move the **Trello** card back to *In Progress*
  - Otherwise, if no changes are needed, the reviewer will **merge** the pull request and move your **Trello** card to *complete*
    
You should ensure your pull request does not contain merge conflicts with the `master` branch. If it does, you need to manually resolve these conflicts by merging `master` **into your feature branch**.