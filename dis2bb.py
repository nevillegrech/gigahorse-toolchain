#!/usr/bin/env python3

import fileinput
from opcodes import *

BLOCK_SEP = "\n---"

class BasicBlock:
  def __init__(self, start=None, end=None):
    self.start = start
    self.end = end
    self.lines = []
    self.parents = []
    self.children = []

  def __len__(self):
    return self.end - self.start

  def __str__(self):
    return "\n".join(str(l) for l in self.lines) + BLOCK_SEP

  def split(self, start):
    """Splits this block into a new block, starting at the specified
    start line number. Returns the new BasicBlock."""
    new_block = BasicBlock(start, self.end)
    self.end = start - 1
    new_block.lines = self.lines[start:]
    self.lines = self.lines[:start]
    self.update_lines()
    new_block.update_lines()
    return new_block

  def update_lines(self):
    """Updates the pointer in each line to point to this block. This is called
    by BasicBlock.split()."""
    for l in self.lines:
      l.block = self

class DisasmLine:
  def __init__(self, pc, opcode, value=None):
    self.pc = int(pc)
    self.opcode = opcode
    self.value = int(value, 16) if value != None else value
    self.block = None

  @staticmethod
  def from_raw(line):
    l = line.split()
    if len(l) > 3:
      return DisasmLine(l[0], l[1], l[3])
    elif len(l) > 1:
      return DisasmLine(l[0], l[1])
    else:
      raise Exception("Invalid disassembly line: " + str(l))

  def __str__(self):
    if self.value is None:
      return "{0} {1}".format(self.pc, self.opcode)
    else:
      return "{0} {1} {2}".format(self.pc, self.opcode, self.value)

  def __repr__(self):
    return "<{0} object {1}: {2}>".format(
      self.__class__.__name__,
      hex(id(self)),
      self.__str__())


def listdict_add(ldict, key, val):
  """Adds a new value to the list in a given list-valued
  dictionary for the given key"""
  if key in ldict:
    ldict[key].append(val)
  else:
    ldict[key] = [val]

lines = [
  DisasmLine.from_raw(l)
  for i, l in enumerate(fileinput.input())
  if i != 0 and len(l.split()) > 1
]

# Mapping of base 10 program counters to line indices
pc2line = {l.pc: i for i, l in enumerate(lines)}

# Mapping of potential leaders (PCs) based on JUMP destinations discovered by
# peephole analysis; in the form: dest PC => [from blocks]
potential_leaders = dict()

# List of DisasmLines which represent JUMPs with an unresolved
# destination address
unresolved_jumps = []

# List of confirmed blocks in the tuple format described below
blocks = []

# block currently being processed
current = BasicBlock(0, len(lines) - 1)

# Linear scan of all DisasmLines to create initial BasicBlocks
for i, l in enumerate(lines):
  l.block = current
  current.lines.append(l)

  if l.opcode == JUMPDEST and l.pc not in potential_leaders:
    potential_leaders[l.pc] = []

  # Flow-altering opcodes indicate end-of-block
  if alters_flow(l.opcode):
    new = current.split(i+1)
    blocks.append(current)

    # For JUMPs, look for the destination in the previous line only!
    # (Peephole analysis)
    if l.opcode in (JUMP, JUMPI):
      if lines[i-1].opcode.startswith(PUSH_PREFIX):
        dest = lines[i-1].value
        listdict_add(potential_leaders, dest, current)
      else:
        unresolved_jumps.append(l)

      # For JUMPI, the next sequential block starting at pc+1 is a possible
      # child of this block in the CFG
      if l.opcode == JUMPI:
        listdict_add(potential_leaders, l.pc + 1, current)

    current = new

# Link BasicBlock CFG nodes by following JUMP destinations
for to_pc, from_blocks in list(potential_leaders.items()):
  to_line = lines[pc2line[to_pc]]
  to_block = to_line.block

  # Leader is in the middle of a block, so split the block
  if pc2line[to_pc] > to_block.start:
    blocks.append(to_block.split(pc2line[to_pc]))
    to_block = blocks[-1]

  # Ignore potential leaders with no known JUMPs coming to them
  if len(from_blocks) > 0:
    for from_block in from_blocks:
      from_block.children.append(to_block)
      to_block.parents.append(from_block)

    potential_leaders.pop(to_pc)
