# TODO: all this functionality can be carefully removed since we don't require
# the need for finding basic blocks during fact generation

import typing as t

import src.opcodes as opcodes


class EVMBasicBlock():
    """
    Represents a single basic block in the control flow graph (CFG), including
    its parent and child nodes in the graph structure.
    """

    def __init__(self, entry: int = None, exit: int = None,
                 evm_ops: t.List['EVMOp'] = None):
        """
        Creates a new basic block containing operations between the
        specified entry and exit instruction counters (inclusive).

        Args:
          entry: block entry point program counter
          exit: block exit point program counter
          evm_ops: a sequence of operations that constitute this BasicBlock's code. Default empty.
        """

        self.evm_ops = evm_ops if evm_ops is not None else []
        """List of EVMOps contained within this EVMBasicBlock"""

        self.fallthrough = None
        """
        The block that this one falls through to on the false branch
        of a JUMPI, if it exists. This should already appear in self.succs;
        this just distinguishes which one is the false branch.
        """
        # TODO: maybe not vital, but this should interact properly with procedure cloning
        self.entry = entry
        self.exit = exit

    def __str__(self):
        """Returns a string representation of this block and all ops in it."""
        super_str = super().__str__()
        op_seq = "\n".join(str(op) for op in self.evm_ops)
        return "\n".join([super_str, self._STR_SEP, op_seq])

    def split(self, entry: int) -> 'EVMBasicBlock':
        """
        Splits current block into a new block, starting at the specified
        entry op index. Returns a new EVMBasicBlock with no preds or succs.

        Args:
          entry: unique index of EVMOp from which the block should be split. The
            EVMOp at this index will become the first EVMOp of the new BasicBlock.
        """
        # Create the new block.
        new = type(self)(entry, self.exit, self.evm_ops[entry - self.entry:])

        # Update the current node.
        self.exit = entry - 1
        self.evm_ops = self.evm_ops[:entry - self.entry]

        # Update the block pointer in each line object
        self.__update_evmop_refs()
        new.__update_evmop_refs()

        return new

    def __update_evmop_refs(self):
        # Update references back to parent block for each opcode
        # This needs to be done when a block is split
        for op in self.evm_ops:
            op.block = self


class EVMOp:
    """
    Represents a single EVM operation.
    """

    def __init__(self, pc: int, opcode: opcodes.OpCode, value: int = None):
        """
        Create a new EVMOp object from the given params which should correspond to
        disasm output.

        Args:
          pc: program counter of this operation
          opcode: VM operation code
          value: constant int value or default None in case of non-PUSH operations

        Each line of disasm output is structured as follows:

        PC <spaces> OPCODE <spaces> => CONSTANT

        where:
          - PC is the program counter
          - OPCODE is an object representing an EVM instruction code
          - CONSTANT is a hexadecimal value with 0x notational prefix
          - <spaces> is a variable number of spaces

        For instructions with no hard-coded constant data (i.e. non-PUSH
        instructions), the disasm output only includes PC and OPCODE; i.e.

        PC <spaces> OPCODE

        If None is passed to the value parameter, the instruction is assumed to
        contain no CONSTANT (as in the second example above).
        """

        self.pc = pc
        """Program counter of this operation"""

        self.opcode = opcode
        """VM operation code"""

        self.value = value
        """Constant int value or None"""

        self.block = None
        """EVMBasicBlock object to which this line belongs"""

    def __str__(self):
        if self.value is None:
            return "{0} {1}".format(hex(self.pc), self.opcode)
        else:
            return "{0} {1} {2}".format(hex(self.pc), self.opcode, hex(self.value))

    def __repr__(self):
        return "<{0} object {1}: {2}>".format(
            self.__class__.__name__,
            hex(id(self)),
            self.__str__()
        )


def blocks_from_ops(ops: t.Iterable[EVMOp]) -> t.Iterable[EVMBasicBlock]:
    """
    Process a sequence of EVMOps and create a sequence of EVMBasicBlocks.

    Args:
      ops: sequence of EVMOps to be put into blocks.

    Returns:
      List of BasicBlocks from the input ops, in arbitrary order.
    """
    blocks = []

    # details for block currently being processed
    entry, exit = (0, len(ops) - 1) if len(ops) > 0 \
        else (None, None)
    current = EVMBasicBlock(entry, exit)

    # Linear scan of all EVMOps to create initial EVMBasicBlocks
    for i, op in enumerate(ops):
        op.block = current
        current.evm_ops.append(op)

        # Flow-altering opcodes indicate end-of-block
        if op.opcode.alters_flow():
            new = current.split(i + 1)
            blocks.append(current)

            # Mark all JUMPs as unresolved
            if op.opcode in (opcodes.JUMP, opcodes.JUMPI):
                current.has_unresolved_jump = True

            # Process the next sequential block in our next iteration
            current = new

        # JUMPDESTs indicate the start of a block.
        # A JUMPDEST should be split on only if it's not already the first
        # operation in a block. In this way we avoid producing empty blocks if
        # JUMPDESTs follow flow-altering operations.
        elif op.opcode == opcodes.JUMPDEST and len(current.evm_ops) > 1:
            new = current.split(i)
            blocks.append(current)
            current = new

        # Always add last block if its last instruction does not alter flow
        elif i == len(ops) - 1:
            blocks.append(current)

    return blocks
