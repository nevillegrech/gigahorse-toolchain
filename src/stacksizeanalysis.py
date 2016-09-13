"""stacksizeanalysis.py: fixed-point static analysis to determine stack sizes
in a CFG"""

import cfglib
import lattice

def block_stack_delta(block:cfglib.EVMBasicBlock):
  """Calculate the net effect on the stack size of executing
  the instruction sequence within a block."""
  delta = 0

  for line in block.lines:
    delta += line.opcode.stack_delta()

  return delta

def run_analysis(cfg:cfglib.EVMOpCFG):
  """Determine the stack size for each basic block within the given CFG
  at both entry and exit points, if it can be known. If there are multiple
  possible stack sizes a value of BOTTOM is instead assigned.

  To calculate this information the entry point of the CFG is assigned a
  stack size of zero, and all others are given an "unknown" value, TOP.
  Then for each block, calculate its entry size by taking the meet of
  the exit sizes of its predecessors. Its own exit size is then its
  entry size plus the delta incurred by the instructions in its body.
  """

  # Stack size information per block at entry and exit points.
  entry_info = {block: lattice.IntLatticeElement.top() for block in cfg.blocks}
  exit_info = {block: lattice.IntLatticeElement.top() for block in cfg.blocks}
  block_deltas = {block: lattice.IntLatticeElement(block_stack_delta(block)) \
                  for block in cfg.blocks}

  # Add a distinguished empty-stack start block which does nothing.
  start_block = cfglib.EVMBasicBlock()
  exit_info[start_block] = lattice.IntLatticeElement(0)

  # We will initialise entry stack size of all blocks with no predecesors
  # to zero in order to reason about the stack within a connected component.
  init_blocks = {cfg.root} | {block for block in cfg.blocks \
                              if len(block.predecessors) == 0}
  for block in init_blocks:
    block.predecessors.append(start_block)

  # Find the fixed point that is the meet-over-paths solution
  queue = list(cfg.blocks)

  while queue:
    current = queue.pop()

    # Calculate the new entry value for the current block.
    new_entry = lattice.IntLatticeElement.meet_all([exit_info[parent] for parent in current.predecessors])

    # If the entry value changed, we have to recompute
    # its exit value, and the entry value for its successors, eventually.
    if new_entry != entry_info[current]:
      entry_info[current] = new_entry
      exit_info[current] = new_entry + block_deltas[current]
      queue += current.successors

  # Remove the start block that was added.
  for block in init_blocks:
    block.predecessors.pop()

  return (entry_info, exit_info)
