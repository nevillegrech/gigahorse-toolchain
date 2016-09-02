from cfglib import *
from lattice import *

def block_stack_delta(block:BasicBlock):
  delta = 0

  for line in block.lines:
    delta += line.opcode.stack_delta()

  return delta

def run_analysis(cfg:ControlFlowGraph):
  # Stack size information per block at entry and exit points.
  entry_info = {block: TOP for block in cfg.blocks}
  exit_info = {block: TOP for block in cfg.blocks}
  block_deltas = {block: IntLatticeElement(block_stack_delta(block)) \
                  for block in cfg.blocks}

  # Add a distinguished start block which does nothing.
  start_block = BasicBlock()
  exit_info[start_block] = IntLatticeElement(0)

  # We will initialise entry stack size of all blocks with no predecesors
  # to zero in order to reason about the stack within a connected component.
  init_blocks = {cfg.root} | {block for block in cfg.blocks \
                              if len(block.parents) == 0}
  for block in init_blocks:
    block.parents.append(start_block)

  # Find the fixed point that is the meet-over-paths solution
  queue = list(cfg.blocks)

  while queue:
    current = queue.pop()

    # Calculate the new entry value for the current block.
    new_entry = meet_all([exit_info[parent] for parent in current.parents])

    # If the entry value changed, we have to recompute
    # its exit value, and the entry value for its children, eventually.
    if new_entry != entry_info[current]:
      entry_info[current] = new_entry
      exit_info[current] = new_entry + block_deltas[current]
      queue += current.children

  # Remove the start block that was added.
  for block in init_blocks:
    block.parents.pop()

  return (entry_info, exit_info)