"""optimise.py: transformers that optimise TAC CFGs"""

import typing
import copy

import tac_cfg
import memtypes as mem
import opcodes

# Intra-block optimisations

# CONSTANT FOLDING AND PROPAGATION

def fold_constants(cfg:tac_cfg.TACGraph):
  """
  Within blocks, propagate constant values and evaluate arithmetic ops on constants.
  Modifies the graph in-place.

  Args:
    tac_cfg: an input graph to be transformed.
  """
  for block in cfg.blocks:
    fold_block_constants(block)

def convert_constant(var_values:typing.Union[mem.Location, mem.Variable],
                     var:typing.Mapping[
                       typing.Union[mem.Location, mem.Variable],
                       mem.Variable
                     ]):
  """
  Apply a mapping from variables and/or storage locations to constant values.
  Return the variable itself if no mapping is available.

  Args:
    var_values: a mapping from variables and locations to constants that they are equivalent to.
    var: the variable to map.
  """
  if isinstance(var, mem.Location):
    copy_loc = copy.copy(var)
    copy_loc.address = convert_constant(var_values, copy_loc.address)
    return copy_loc
  elif var in var_values:
    return copy.copy(var_values[var])
  else:
    return copy.copy(var)

def fold_block_constants(block:tac_cfg.TACBasicBlock):
  """
  Propagate constants and evaluate arithmetic ops with constant args in a block.
  Modifies the block in place.
  """
  var_values = {}

  for op in block.tac_ops:
    # Evaluate constant values in args and mem locations
    op.args = [convert_constant(var_values, arg) for arg in op.args]
    if isinstance(op, tac_cfg.TACAssignOp):
      op.lhs = convert_constant(var_values, op.lhs)

    # Evaluate arithmetic ops and update the mapping if we can
    if op.const_args():
      if op.opcode.is_arithmetic():

        # Obtain the appropriate arithmetic operation by name from the Constant class methods
        # and apply it to the op arguments.
        val = mem.Variable.arith_op(op.opcode.name, op.args)

        var_values[op.lhs] = val
        op.opcode = opcodes.CONST
        op.args = [val]

      # Here we could add MSTORE, MSTORE8, SSTORE dests to the environment
      # if we could be assured there were no calculated addresses, since
      # such addresses could potentially overwrite any data in memory.
      if op.opcode == opcodes.CONST:
          var_values[op.lhs] = op.args[0]

  # Convert the stack with the final mapping.
  block.stack_adds = [convert_constant(var_values, var)
                      for var in block.stack_adds]



# TODO: update the const_args concept to include many-valued vars
def apply_operations(cfg):
  for block in cfg.blocks:
    for op in block.tac_ops:
      if op.opcode == opcodes.CONST:
        op.lhs.values = op.args[0].values
      elif op.const_args() and op.opcode.is_arithmetic():
        result = mem.Variable.arith_op(op.opcode.name, op.args)
        op.lhs.values = result.values

