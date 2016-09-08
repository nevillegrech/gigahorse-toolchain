"""optimise.py: transformers that optimise TAC CFGs"""

import tac

# Things to Add
# jump optimisations
# basic block stratification
# Recompute graph from jump dests
# block straightening
# Algebraic Simplifications
# Copy propagation
# Dead code
# Unreachable Code


# Intra-block optimisations

# CONSTANT FOLDING AND PROPAGATION

def fold_constants(cfg):
  """
  Within blocks, propagate constant values and evaluate arithmetic ops on constants.
  """
  for block in cfg.blocks:
    fold_block_constants(block)

def convert_constant(var_values, var):
  """
  Apply a mapping from variables and/or storage locations to constant values.
  """
  from copy import copy
  if isinstance(var, tac.Location):
    copy_loc = copy(var)
    copy_loc.address = convert_constant(var_values, copy_loc.address)
    return copy_loc
  elif var in var_values:
    return copy(var_values[var])
  else:
    return copy(var)

def fold_block_constants(block):
  """
  Propagate constants and evaluate arithmetic ops with constant args in a block.
  """
  var_values = {}

  for op in block.ops:
    # Evaluate constant values in args and mem locations
    op.args = [convert_constant(var_values, arg) for arg in op.args]
    if isinstance(op, tac.TACAssignOp):
      op.lhs = convert_constant(var_values, op.lhs)

    # Evaluate arithmetic ops and update the mapping if we can
    if op.const_args():
      if op.is_arithmetic():
        val = getattr(tac.Constant, op.name)(*op.args)
        var_values[op.lhs] = val
        op.name = "CONST"
        op.args = [val]

      # Here we could add MSTORE, MSTORE8, SSTORE dests to the environment
      # if we could be assured there were no calculated addresses, since
      # such addresses could potentially overwrite any data in memory.
      if op.name in ["CONST"]:
          var_values[op.lhs] = op.args[0]

  # Convert the stack with the final mapping.
  block.stack_adds = [convert_constant(var_values, var)
                      for var in block.stack_adds]

