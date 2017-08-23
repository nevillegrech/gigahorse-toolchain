"""blockparse.py: Parse operation sequences and construct basic blocks"""

import abc
import typing as t

import cfg
import evm_cfg
import opcodes
import logging

ENDIANNESS = "big"
"""
The endianness to use when parsing hexadecimal or binary files.
"""


class BlockParser(abc.ABC):
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
  def parse(self) -> t.Iterable[cfg.BasicBlock]:
    """
    Parses the raw input object and returns an iterable of BasicBlocks.
    """
    self._ops = []


class EVMDasmParser(BlockParser):
  def __init__(self, dasm:t.Iterable[str]):
    """
    Parses raw EVM disassembly lines and creates corresponding EVMBasicBlocks.
    This does NOT follow jumps or create graph edges - it just parses the
    disassembly and creates the blocks.

    Args:
      dasm: iterable of raw disasm output lines to be parsed by this instance
    """
    super().__init__(dasm)

  def parse(self, strict: bool = False):
    """
    Args:
      strict: if True, will fail and produce no output when given malformed
        input (instead of producing a warning and ignoring the malformed input)
    """
    super().parse()

    # Construct a list of EVMOp objects from the raw input disassembly
    # lines, ignoring the first line of input (which is the bytecode's hex
    # representation when using Ethereum's disasm tool). Any line which does
    # not produce enough tokens to be valid disassembly after being split() is
    # also ignored.
    for i, l in enumerate(self._raw):
      if len(l.split()) == 1:
        logging.debug("Line %s: invalid disassembly:\n   %s", i+1, l.rstrip())
        if strict:
          raise RuntimeError("Line {}: invalid disassembly {}".format(i+1, l))
        continue
      elif len(l.split()) < 1:
        if strict:
          logging.warning("Line %s: empty disassembly.", i+1)
          raise RuntimeError("Line {}: empty disassembly.".format(i+1))
        continue

      try:
        self._ops.append(self.evm_op_from_dasm(l))
      except (ValueError, LookupError, NotImplementedError) as e:
        logging.debug("Line %s: invalid disassembly:\n   %s", i+1, l.rstrip())
        if strict:
            raise e

    return evm_cfg.blocks_from_ops(self._ops)

  @staticmethod
  def evm_op_from_dasm(line:str) -> evm_cfg.EVMOp:
    """
    Creates and returns a new EVMOp object from a raw line of disassembly.

    Args:
      line: raw line of output from Ethereum's disasm disassembler.

    Returns:
      evm_cfg.EVMOp: the constructed EVMOp
    """
    toks = line.replace("=>", " ").split()

    # Convert hex PCs to ints
    if toks[0].startswith("0x"):
      toks[0] = int(toks[0], 16)

    if len(toks) > 2:
      val = int(toks[2], 16)
      try:
        return evm_cfg.EVMOp(int(toks[0]), opcodes.opcode_by_name(toks[1]), val)
      except LookupError as e:
        return evm_cfg.EVMOp(int(toks[0]), opcodes.missing_opcode(val), val)
    elif len(toks) > 1:
        return evm_cfg.EVMOp(int(toks[0]), opcodes.opcode_by_name(toks[1]))
    else:
      raise NotImplementedError("Could not parse unknown disassembly format:" +
                                  "\n    {}".format(line))


class EVMBytecodeParser(BlockParser):
  def __init__(self, bytecode: t.Union[str, bytes]):
    """
    Parse EVM bytecode directly into basic blocks.

    Args:
      bytecode: EVM bytecode, either as a hexadecimal string or a bytes
        object. If given as a hex string, it may optionally start with 0x.
    """
    super().__init__(bytecode)

    if type(bytecode) is str:
      bytecode = bytes.fromhex(bytecode.replace("0x", ""))
    else:
      bytecode = bytes(bytecode)

    self._raw = bytecode

    # Track the program counter as we traverse the bytecode
    self.__pc = 0

  def __consume(self, n):
    bytes_ = self._raw[self.__pc : self.__pc + n]
    self.__pc += n
    return bytes_

  def __has_more_bytes(self):
    return self.__pc < len(self._raw)

  def parse(self, strict: bool = False) -> t.Iterable[evm_cfg.EVMBasicBlock]:
    """
    Args:
      strict: if True, will fail and produce no output when given malformed
        input (instead of producing a warning and ignoring the malformed input)
    """
    super().parse()

    while self.__has_more_bytes():
      pc = self.__pc
      byte = int.from_bytes(self.__consume(1), ENDIANNESS)
      const, const_size = None, 0

      try:
        # try to resolve the byte to an opcode
        op = opcodes.opcode_by_value(byte)

      except LookupError as e:
        # oops, unknown opcode
        if strict:
          logging.warning("(strict) Invalid opcode at PC = %#02x: %s", pc, str(e))
          raise e
        # not strict, so just log:
        logging.debug("Invalid opcode at PC = %#02x: %s", pc, str(e))
        op = opcodes.missing_opcode(byte)
        const = byte

      # push codes have an argument
      if op.is_push():
        const_size = op.push_len()

      # for opcodes with an argument, consume the argument
      if const_size > 0:
        const = int.from_bytes(self.__consume(const_size), ENDIANNESS)

      self._ops.append(evm_cfg.EVMOp(pc, op, const))

    # build basic blocks from the sequence of opcodes
    return evm_cfg.blocks_from_ops(self._ops)
