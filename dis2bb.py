#!/usr/bin/env python3

# Standard lib imports
import fileinput

# Local project imports
from cfglib import ControlFlowGraph
from stacksizeanalysis import run_analysis, block_stack_delta
from destackify import Destackifier
import optimise

lines = []

with open("examples/basic.disasm", 'r') as evm_file:
  lines = evm_file.readlines()


cfg = ControlFlowGraph(lines) #fileinput.input())
entry, exit = run_analysis(cfg)
destack = Destackifier()

for block in cfg.blocks:
  print("Entry stack:", entry[block])
  print()
  print(block)
  print(block_stack_delta(block), "stack elements added.")
  print("Exit stack:", exit[block])
  print()

  print("TAC code:\n")
  converted_block = destack.convert_block(block)
  for op in converted_block.ops:
    print(str(op))
  print("\nNew stack head:", [str(var) for var \
                              in converted_block.stack_additions])
  print("Popped from initial stack:", converted_block.stack_pops)
  print("Constant Optimised:\n")
  optimise.fold_block_constants(converted_block)
  for op in converted_block.ops:
    print(str(op))

  print("\n-----\n")

