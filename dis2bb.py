#!/usr/bin/env python3

# Standard lib imports
import fileinput

# Local project imports
from cfglib import *

from stacksizeanalysis import *

cfg = ControlFlowGraph(fileinput.input())


entry, exit = run_analysis(cfg)

for block in cfg.blocks:
	print("----")
	print(entry[block])
	print(block)
	print(block_stack_delta(block))
	print(exit[block])
