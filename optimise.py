# optimise.py: transformers that optimise TAC CFGs

from tac import is_arithmetic, Constant, Location, TACAssignOp

# Intra-block optimisations

def fold_constants(cfg):
	for block in cfg:
		fold_block_contants(block)

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
		# Evaluate constant values in args
		op.args = [convert_constant(var_values, arg) for arg in op.args]

		if isinstance(op, TACAssignOp):
			op.lhs = convert_constant(var_values, op.lhs)

		# update the mapping if we can
		if op.name == "CONST":
			var_values[op.lhs] = op.args[0]
		if is_arithmetic(op):
			if all([isinstance(arg, Constant) for arg in op.args]):
				val = getattr(Constant, op.name)(*op.args)
				var_values[op.lhs] = val
				op.name = "CONST"
				op.args = [val]

	block.stack_additions = [convert_constant(var_values, var) \
													 for var in block.stack_additions]