# optimise.py: transformers that optimise TAC CFGs

from tac import is_arithmetic, Constant

# Intra-block optimisations

def fold_constants(cfg):
	for block in cfg:
		fold_block_contants(block)

def fold_block_constants(block):
	var_values = {}

	for op in block.ops:
		# Evaluate constant values in args
		op.args = [var_values[arg] if arg in var_values else arg for arg in op.args]

		# update the mapping if we can
		if op.name == "CONST":
			var_values[op.lhs] = op.args[0]
		if is_arithmetic(op):
			if all([isinstance(arg, Constant) for arg in op.args]):
				val = getattr(Constant, op.name)(*op.args)
				var_values[op.lhs] = val
				op.name = "CONST"
				op.args = [val]

	block.stack_additions = [var_values[val] if val in var_values else val \
													 for val in block.stack_additions]