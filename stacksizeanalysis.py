from cfglib import BasicBlock

def block_stack_delta(block:BasicBlock):
	delta = 0

	for line in block.lines:
		delta += line.opcode.stack_delta()

	return stack_delta