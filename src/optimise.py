"""optimise.py: transformers that optimise TAC CFGs"""

import typing

import tac_cfg
import opcodes

# Intra-block optimisations

# CONSTANT FOLDING AND PROPAGATION

def fold_constants(cfg:tac_cfg.TACGraph):
  """
  Within blocks, propagate constant values and evaluate arithmetic ops on constants.
  """
  for block in cfg.blocks:
    fold_block_constants(block)

VarOrLoc = typing.Union[tac_cfg.Location, tac_cfg.Variable]
VarValMapping = typing.Mapping[VarOrLoc, tac_cfg.Constant]
def convert_constant(var_values:VarValMapping, var:VarOrLoc):
  """
  Apply a mapping from variables and/or storage locations to constant values.
  """
  from copy import copy
  if isinstance(var, tac_cfg.Location):
    copy_loc = copy(var)
    copy_loc.address = convert_constant(var_values, copy_loc.address)
    return copy_loc
  elif var in var_values:
    return copy(var_values[var])
  else:
    return copy(var)

def fold_block_constants(block:tac_cfg.TACBasicBlock):
  """
  Propagate constants and evaluate arithmetic ops with constant args in a block.
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
        val = getattr(tac_cfg.Constant, op.opcode.name)(*op.args)
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
