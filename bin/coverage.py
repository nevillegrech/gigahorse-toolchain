from os import listdir
from os.path import abspath, dirname, join
import sys
import itertools

src_path = join(dirname(abspath(__file__)), "../src")
sys.path.insert(0, src_path)

# Local project imports
import exporter
import dataflow
import tac_cfg

d = '../../contract_dump/contracts'
start = 0
stop = 100

runtime_files = filter(lambda f: f.endswith("runtime.hex"), listdir(d))

sliced = itertools.islice(runtime_files, start, stop)

unresolved = 0
all_contracts = 0

for filename in sliced:
  print("Handling file {}.".format(filename))
  with open(join(d, filename)) as f:
    all_contracts += 1
    cfg = tac_cfg.TACGraph.from_bytecode(f)
    dataflow.stack_analysis(cfg)
    dataflow.stack_analysis(cfg)
    dataflow.stack_analysis(cfg)
    dataflow.stack_analysis(cfg)

    if cfg.has_unresolved_jump:
      unresolved += 1
      for b in cfg.blocks:
        b.preds.sort(key=lambda k: k.ident())
        b.succs.sort(key=lambda k: k.ident())
      print("Contains UNRESOLVED jumps!".format(filename))
      open("unresolved/" + filename + ".txt", 'w').write(exporter.CFGStringExporter(cfg).export())
      exporter.CFGDotExporter(cfg).export("unresolved/" + filename + ".png")
      exporter.CFGDotExporter(cfg).export("unresolved/" + filename + ".svg")


print(unresolved/all_contracts)

