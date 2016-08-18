# cfglib.py: Classes for processing Ethereum disasm output and building a CFG

# Local project imports
import utils
from opcodes import *

# Separator to be used for string representation of blocks
BLOCK_SEP = "\n---"

class ControlFlowGraph:
  def __init__(self, disasm:iter):
    # List of BasicBlock objects contained in the CFG
    self.blocks = []

    # Mapping of potential leaders (stored as base-10 PC values) based on JUMP
    # destinations discovered by peephole analysis; in the form:
    #   PC => list(BasicBlocks)
    self.potential_leaders = dict()

    # List of DisasmLines which represent JUMPs with an unresolved destination
    # address Either these jumps use computed addresses, or the destination is
    # pushed to the stack in a previous block.
    self.unresolved_jumps = []

    # Parse disassembly and set root/entry block of the CFG, containing PC 0
    self.root = self.__parse_disassembly(disasm)

  def __len__(self):
    return len(self.blocks)

  def __str__(self):
    return "\n".join(str(b) for b in self.blocks)

  def __parse_disassembly(self, disasm):
    # Construct a list of DisasmLine objects from the raw input disassembly
    # lines, ignoring the first line of input (which is the bytecode's hex
    # representation when using Ethereum's disasm tool). Any line which does
    # not produce enough tokens to be valid disassembly after being split() is
    # also ignored.
    lines = [
      DisasmLine.from_raw(l)
      for i, l in enumerate(disasm)
      if i != 0 and len(l.split()) > 1
    ]

    # Mapping of base 10 program counters to line indices (Used for mapping
    # jump destinations to actual disassembly lines)
    pc2line = {l.pc: i for i, l in enumerate(lines)}

    self.__create_blocks(lines, pc2line)
    self.__create_edges(lines, pc2line)

    # Return the "root" or "entry" block if it exists, or None
    return self.blocks[0] if len(self.blocks) > 0 else None

  def __create_blocks(self, lines, pc2line):
    # block currently being processed
    current = BasicBlock(0, len(lines) - 1)

    # Linear scan of all DisasmLines to create initial BasicBlocks
    for i, l in enumerate(lines):
      l.block = current
      current.lines.append(l)

      if l.opcode == JUMPDEST and l.pc not in self.potential_leaders:
        self.potential_leaders[l.pc] = []

      # Flow-altering opcodes indicate end-of-block
      if alters_flow(l.opcode):
        new = current.split(i+1)
        self.blocks.append(current)

        # For JUMPs, look for the destination in the previous line only!
        # (Peephole analysis)
        if l.opcode in (JUMP, JUMPI):
          if lines[i-1].opcode.startswith(PUSH_PREFIX):
            dest = lines[i-1].value
            utils.listdict_add(self.potential_leaders, dest, current)
          else:
            self.unresolved_jumps.append(l)

          # For JUMPI, the next sequential block starting at pc+1 is a
          # possible child of this block in the CFG
          if l.opcode == JUMPI:
            utils.listdict_add(self.potential_leaders, l.pc + 1, current)

        # Process the next sequential block in our next iteration
        current = new

  def __create_edges(self, lines, pc2line):
    # Link BasicBlock CFG nodes by following JUMP destinations
    for to_pc, from_blocks in list(self.potential_leaders.items()):
      to_line = lines[pc2line[to_pc]]
      to_block = to_line.block

      # Leader is in the middle of a block, so split the block
      if pc2line[to_pc] > to_block.start:
        self.blocks.append(to_block.split(pc2line[to_pc]))
        to_block = self.blocks[-1]

      # Ignore potential leaders with no known JUMPs coming to them
      if len(from_blocks) > 0:
        for from_block in from_blocks:
          from_block.children.append(to_block)
          to_block.parents.append(from_block)

        # We've dealt with this leader, remove it from potential_leaders
        self.potential_leaders.pop(to_pc)

class BasicBlock:
  """
  Represents a single basic block in the control flow graph (CFG), including
  its parent and child nodes in the graph structure.
  """
  def __init__(self, start:int=None, end:int=None):
    """Creates a new basic block containing disassembly lines between the
    specified start index and the specified end index (inclusive)."""
    self.start = start
    self.end = end
    # DisasmLine objects contained in this block's range
    self.lines = []
    # BasicBlock objects which pass control to this block
    self.parents = []
    # BasicBlock objects which this block passes control to
    self.children = []

  def __len__(self):
    """Returns the number of DisasmLines contained within this block."""
    return self.end - self.start

  def __str__(self):
    """Returns a string representation of this block and all lines in it."""
    # str(BasicBlock) is as a newline-separated list of str(DisasmLine)
    # with the BLOCK_SEP appended after the last line
    return "\n".join(str(l) for l in self.lines) + BLOCK_SEP

  def split(self, start:int):
    """Splits this block into a new block, starting at the specified
    start line number. Returns the new BasicBlock."""
    # Create the new block and assign the line ranges
    new_block = BasicBlock(start, self.end)
    self.end = start - 1
    # Split the disasm lines
    new_block.lines = self.lines[start:]
    self.lines = self.lines[:start]
    # Update the block pointer in each line object
    self.update_lines()
    new_block.update_lines()
    return new_block

  def update_lines(self):
    """Updates the pointer in each DisasmLine object to point to this block.
    This is called by BasicBlock.split() after a split to correct any
    references to the original (pre-split) block."""
    for l in self.lines:
      l.block = self

class DisasmLine:
  """Represents a single line of EVM bytecode disassembly as produced by the
  official Ethereum 'disasm' disassembler."""
  def __init__(self, pc:str, opcode:str, value:str=None):
    """Create a new DisasmLine object from the given strings which should
    correspond to disasm output. Each line of disasm output is structured as
    follows:
              PC <spaces> OPCODE <spaces> => CONSTANT
    where:
            PC is the program counter (base 10 integer)
        OPCODE is a textual representation of an EVM instruction code
      CONSTANT is a hexadecimal value with 0x notational prefix
      <spaces> is a variable number of spaces
    For instructions with no hard-coded constant data (i.e. non-PUSH
    instructions), the disasm output only includes PC and OPCODE; i.e.
              PC <spaces> OPCODE

    If None is passed to the value parameter, the instruction is assumed to
    contain no CONSTANT (as in the second example above).
    """
    # Program counter, stored as a base-10 int
    self.pc = int(pc)
    # VM operation code, stored as a string
    self.opcode = opcode
    # Constant value, stored as a base-10 int or None
    self.value = int(value, 16) if value != None else value
    # BasicBlock object to which this line belongs
    self.block = None

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

  @staticmethod
  def from_raw(line:str):
    """Creates and returns a new BasicBlock object from a raw line of
    disassembly. The line should be from Ethereum's disasm disassembler."""
    l = line.split()
    if len(l) > 3:
      return DisasmLine(l[0], l[1], l[3])
    elif len(l) > 1:
      return DisasmLine(l[0], l[1])
    else:
      raise Exception("Could not parse invalid disassembly format: " + str(l))

