"""blockparse.py: Parse operation sequences and construct basic blocks"""

import typing

import abc
import cfg
import utils
import evm_cfg
import opcodes

class BlockParser(abc.ABC):
  """
  """
  @abc.abstractmethod
  def __init__(self, raw:object):
    """
    """
    self._raw = raw
    self._ops = []

  @abc.abstractmethod
  def parse(self) -> typing.Iterable[cfg.BasicBlock]:
    """
    """

  @classmethod
  def do_parse(cls, raw:object) -> typing.Iterable[cfg.BasicBlock]:
    """
    Convenience method which instantiates this BlockParser with the given raw
    input object and returns the result of parse().

    Args:
      raw: parser-specific object containing raw input to be parsed.
    """
    parser = cls(raw)
    return parser.parse()

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

    self.__pc2op = dict()
    """
    Mapping of program counters to line indices (Used for mapping jump
    destinations to actual disassembly lines)
    """

    self.__blocks = []

  def parse(self):
    super().parse()

    # Construct a list of EVMOp objects from the raw input disassembly
    # lines, ignoring the first line of input (which is the bytecode's hex
    # representation when using Ethereum's disasm tool). Any line which does
    # not produce enough tokens to be valid disassembly after being split() is
    # also ignored.
    self._ops = [
      self.evm_op_from_dasm(l)
      for i, l in enumerate(self._raw)
      if i != 0 and len(l.split()) > 1
    ]

    self.__blocks = []
    self.__pc2op = {l.pc: i for i, l in enumerate(self._ops)}
    self.__create_blocks()

    return self.__blocks

  def __create_blocks(self):
    # block currently being processed
    current = evm_cfg.EVMBasicBlock(0, len(self._ops) - 1)

    # Linear scan of all EVMOps to create initial EVMBasicBlocks
    for i, op in enumerate(self._ops):
      op.block = current
      current.evm_ops.append(op)

      # Flow-altering opcodes indicate end-of-block
      if op.opcode.alters_flow():
        current, new = self.__split_block(current, i+1)
        self.__blocks.append(current)

        # Mark all JUMPs as unresolved
        if op.opcode in (opcodes.JUMP, opcodes.JUMPI):
          current.has_unresolved_jump = True

        # Process the next sequential block in our next iteration
        current = new

      # Always add last block if its last instruction does not alter flow
      elif i == len(self._ops) - 1:
        self.__blocks.append(current)

  def __split_block(self, block, entry:int) -> \
      typing.Tuple[evm_cfg.EVMBasicBlock, evm_cfg.EVMBasicBlock]:
    """
    Splits given block into a new block, starting at the specified
    entry line number. Returns two EVMBasicBlocks.
    """
    # Create the new block and assign the code line ranges
    new = type(block)(entry, block.exit)
    block.exit = entry - 1

    # Split the code lines between the two nodes
    new.evm_ops = block.evm_ops[entry-block.entry:]
    block.evm_ops = block.evm_ops[:entry-block.entry]

    # Update the block pointer in each line object
    self.__update_evmop_block_refs(block)
    self.__update_evmop_block_refs(new)

    return block, new

  def __update_evmop_block_refs(self, block):
    # Update references back to parent block for each opcode
    # This needs to be done when a block is split
    for op in block.evm_ops:
      op.block = block

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
