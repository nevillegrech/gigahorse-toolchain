#!/usr/bin/env python3

# Standard lib imports
import fileinput

# Local project imports
from cfglib import *

from destackify import *

cfg = ControlFlowGraph(fileinput.input())

#print(cfg)

destack = Destackifier()

for block in cfg.blocks:
	print(block)

	ops, stack, num = destack.convert_block(block)

	for op in ops:
		print(str(op))

	print()
	print(stack)
	print(num)

	print("\n-----\n")


