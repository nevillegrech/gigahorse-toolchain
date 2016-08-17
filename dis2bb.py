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
    return new_block

class DisasmLine:
  def __init__(self, pc, opcode, value=None):
    self.pc = int(pc)
    self.opcode = opcode
    self.value = int(value, 16) if value != None else value

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


lines = [
  DisasmLine.from_raw(l)
  for i, l in enumerate(fileinput.input())
  if i != 0 and len(l.split()) > 1
]

# List of program counters (base 10) with unresolved block membership
potential_leaders = []
potential_splits = []

# List of confirmed blocks in the tuple format described below
blocks = []

# block currently being processed: (first_line_index, last_line_index)
current = BasicBlock(0, len(lines) - 1)

for i, l in enumerate(lines):
  if i == 0:
    continue

  current.lines.append(l)

  if alters_flow(l.opcode):
    new = current.split(i+1)
    blocks.append(current)

    # For JUMPs, look for the destination in the previous line only!
    # (Peephole analysis)
    if l.opcode in (JUMP, JUMPI) and lines[i-1].opcode.startswith(PUSH_PREFIX):
      dest = lines[i-1].value
      if dest > l.pc:
        potential_leaders.append(dest)
      else:
        potential_splits.append(dest)

    current = new
