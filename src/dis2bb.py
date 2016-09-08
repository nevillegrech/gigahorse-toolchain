#!/usr/bin/env python3

# Standard lib imports
import fileinput

# Local project imports
from cfglib import ControlFlowGraph
from stacksizeanalysis import run_analysis, block_stack_delta
from destackify import Destackifier
import optimise
import tac
import utils

cfg = ControlFlowGraph(fileinput.input())

taccfg = tac.TACCFG(cfg)
optimise.fold_constants(taccfg)
taccfg.recheck_jumps()

blocks = zip(sorted(cfg.blocks, key=lambda block: block.lines[0].pc),
             sorted(taccfg.blocks, key=lambda block: block.entry))

for evm, tac in blocks:
  print(evm)
  print(tac)
  print()

