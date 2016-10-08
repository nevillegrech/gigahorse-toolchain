"""blockparse.py: Parse operation sequences and construct basic blocks"""

import abc
import typing

import cfg
import evm_cfg
import opcodes
import logging

class BlockParser(abc.ABC):
  """
  """
  @abc.abstractmethod
  def __init__(self, raw:object):
    """
    Constructs a new BlockParser for parsing the given raw input object.

    Args:
      raw: parser-specific object containing raw input to be parsed.
    """

    self._raw = raw
    """raw: parser-specific object containing raw input to be parsed."""

    self._ops = []
    """
    List of program operations extracted from the raw input object.
    Indices from this list are used as unique identifiers for program
    operations when constructing BasicBlocks.
    """

  @abc.abstractmethod
  def parse(self) -> typing.Iterable[cfg.BasicBlock]:
    """
    Parses the raw input object and returns an iterable of BasicBlocks.
    """


class EVMBlockParser(BlockParser):
  def __init__(self, dasm:typing.Iterable[str]):
    """
    Parses raw EVM disassembly lines and creates corresponding EVMBasicBlocks.
    This does NOT follow jumps or create graph edges - it just parses the
    disassembly and creates the blocks.

    Args:
      dasm: iterable of raw disasm output lines to be parsed by this instance
    """
    super().__init__(dasm)

    self.__blocks = []

  def parse(self):
    super().parse()

    self._ops = []

    # Construct a list of EVMOp objects from the raw input disassembly
    # lines, ignoring the first line of input (which is the bytecode's hex
    # representation when using Ethereum's disasm tool). Any line which does
    # not produce enough tokens to be valid disassembly after being split() is
    # also ignored.
    for i, l in enumerate(self._raw):
      if len(l.split()) == 1:
        logging.log("Warning (line {}): skipping invalid disassembly:\n   {}"
                    .format(i+1, l.rstrip()))
        continue
      elif len(l.split()) < 1:
        continue
      self._ops.append(self.evm_op_from_dasm(l))

    self.__blocks = []
    self.__create_blocks()

    return self.__blocks

  def __create_blocks(self):
    # block currently being processed
    entry, exit = (0, len(self._ops) - 1) if len(self._ops) > 0 \
                  else (None, None)
    current = evm_cfg.EVMBasicBlock(entry, exit)

    # Linear scan of all EVMOps to create initial EVMBasicBlocks
    for i, op in enumerate(self._ops):
      op.block = current
      current.evm_ops.append(op)

      # Flow-altering opcodes indicate end-of-block
      if op.opcode.alters_flow():
        new = current.split(i+1)
        self.__blocks.append(current)

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
        self.__blocks.append(current)
        current = new

      # Always add last block if its last instruction does not alter flow
      elif i == len(self._ops) - 1:
        self.__blocks.append(current)

  @staticmethod
  def evm_op_from_dasm(line:str) -> evm_cfg.EVMOp:
    """
    Creates and returns a new EVMOp object from a raw line of disassembly.

    Args:
      line: raw line of output from Ethereum's disasm disassembler.

    Returns:
      evm_cfg.EVMOp: the constructed EVMOp
    """
    l = line.split()
    if len(l) > 3:
      return evm_cfg.EVMOp(int(l[0]), opcodes.opcode_by_name(l[1]), int(l[3], 16))
    elif len(l) > 1:
      return evm_cfg.EVMOp(int(l[0]), opcodes.opcode_by_name(l[1]))
    else:
      raise NotImplementedError("Could not parse unknown disassembly format: " + str(l))
