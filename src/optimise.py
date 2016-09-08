"""optimise.py: transformers that optimise TAC CFGs"""

from tac import Constant, Location, TACAssignOp

# Things to Add
# Constant Propagation - DONE
# recalculate jump destinations (should only add new dests to unresolved jumps)
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
	for block in cfg.blocks:
		fold_block_constants(block)

def convert_constant(var_values, var):
	if isinstance(var, Location):
		copy_loc = var.copy()
		copy_loc.address = convert_constant(var_values, copy_loc.address)
		return copy_loc
	elif var in var_values:
		return var_values[var].copy()
	else:
		return var.copy()

def fold_block_constants(block):
	var_values = {}

	for op in block.ops:
		# Evaluate constant values in args and mem locations
		op.args = [convert_constant(var_values, arg) for arg in op.args]
		if isinstance(op, TACAssignOp):
			op.lhs = convert_constant(var_values, op.lhs)

		# Evaluate arithmetic ops and update the mapping if we can
		if op.const_args():
			if op.is_arithmetic():
				val = getattr(Constant, op.name)(*op.args)
				var_values[op.lhs] = val
				op.name = "CONST"
				op.args = [val]

			# Here could add MSTORE, MSTORE8, SSTORE dests to the environment
			# if we could be assured there were no calculated addresses, since
			# such addresses could potentially overwrite any data in memory.
			if op.name in ["CONST"]:
					var_values[op.lhs] = op.args[0]

	# Convert the stack with the final mapping.
	block.stack_additions = [convert_constant(var_values, var) \
													 for var in block.stack_additions]

