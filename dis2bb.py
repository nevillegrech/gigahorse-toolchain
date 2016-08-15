#!/usr/bin/env python3

import fileinput
from opcodes import *

lines = [l.split()
         for i, l in enumerate(fileinput.input())
         if i != 0]

# List of program counters (base 10) with unresolved block membership
potential_leaders = []
potential_splits = []

# List of confirmed blocks in the tuple format described below
blocks = []

# block currently being processed: (first_line_index, last_line_index)
current = (0, None)

for i, l in enumerate(lines):
  if i == 0:
    continue

  if alters_flow(l[1]):
    current[1] = i
    blocks.append(current)
    current = (i + 1, None)

    # For JUMPs, look for the destination in the previous line only!
    # (Peephole analysis)
    if l[1] in (JUMP, JUMPI) and lines[i-1][1].startswith(PUSH_PREFIX):
      dest = int(lines[i-1][3], 16)
      if dest > i:
        potential_leaders.append(dest)
      else:
        potential_splits.append(dest)

if blocks[-1][1] is None:
  blocks[-1][1] = len(lines) - 1
