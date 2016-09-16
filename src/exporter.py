"""exporter.py: abstract classes for exporting decompiler state"""

import abc

import cfg
import tac_cfg
import patterns
import opcodes
import memtypes

import csv

class Exporter(abc.ABC):
  @abc.abstractmethod
  def export(self):
    """
    Abstract method which performs the final export using state collected
    during visitations.
    """


class CFGTsvExporter(Exporter, patterns.Visitor):
  def __init__(self):
    self.nodes = []
    self.ops = []
    self.edges = []
    self.defined = []
    self.reads = []
    self.writes = []

  def visit(self, node):
    self.nodes.append(node)

    # Add edges from predecessor exits to this node's entry
    for pred in node.preds:
      # Generating edge.facts
      self.edges.append((hex(pred.exit), hex(node.entry)))

    # Keep track of previous TACOp for building edges
    prev_tac = None

    for tac in node.tac_ops:

      # Add edges between TACOps (generate edge.facts)
      if prev_tac != None:
        # Generating edge.facts
        self.edges.append((hex(prev_tac.pc), hex(tac.pc)))
      prev_tac = tac

      # Generate op.facts
      self.ops.append((hex(tac.pc), tac.opcode))

      if isinstance(tac, tac_cfg.TACAssignOp):

        # Memory assignments are not considered as 'variable definitions'
        if not isinstance(tac.lhs, memtypes.Location):

          # Generate defined.facts
          self.defined.append((hex(tac.pc), tac.lhs))

        # TODO -- Add notion of blockchain and local memory
        # Generate write.facts
        self.writes.append((hex(tac.pc), tac.lhs))

      for arg in tac.args:

        # Only include variable reads; ignore constants
        if not arg.is_const:

          # Generate read.facts
          self.reads.append((hex(tac.pc), arg))

  def export(self):
    # Inner function for DRYness
    def generate(filename, entries):
      with open(filename, 'w') as f:
        writer = csv.writer(f, delimiter='\t')
        for e in entries:
          writer.writerow(e)

    generate('op.facts', self.ops)
    generate('defined.facts', self.defined)
    generate('read.facts', self.reads)
    generate('write.facts', self.writes)
    generate('edge.facts', self.edges)

    # Note: Start and End are currently singletons
    # TODO -- Update starts and ends to be based on function boundaries
    with open('start.facts', 'w') as f:
      print(hex(self.nodes[0].entry), file=f)
    with open('end.facts', 'w') as f:
      print(hex(self.nodes[-1].exit), file=f)


class CFGPrintExporter(Exporter, patterns.Visitor):
  def __init__(self, ordered=True):
    self.ordered = ordered
    self.nodes = []

  def visit(self, node):
    self.nodes.append((node.entry, str(node)))

  def export(self):
    if self.ordered:
      self.nodes.sort(key=lambda n: n[0])
    for n in self.nodes:
      print(n[1])


class CFGDotExporter(Exporter):
  def export(self, cfg:tac_cfg.TACGraph, out_filename:str="cfg.dot"):
    """From a CFG, generate a dotfile for drawing a pretty picture of it."""
    import networkx as nx
    from networkx.drawing.nx_pydot import write_dot
    G = nx.DiGraph()
    G.add_nodes_from(b.ident() for b in cfg.blocks)
    G.add_edges_from((p, s) for p, s in cfg.edge_list())
    G.add_edges_from((block.ident(), "?") for block in cfg.blocks \
                     if block.has_unresolved_jump)

    returns = {block.ident(): "green" for block in cfg.blocks \
               if block.tac_ops[-1].opcode == opcodes.RETURN}
    stops = {block.ident(): "blue" for block in cfg.blocks \
             if block.tac_ops[-1].opcode == opcodes.STOP}
    throws = {block.ident(): "red" for block in cfg.blocks \
             if block.tac_ops[-1].opcode in [opcodes.THROW, opcodes.THROWI]}
    suicides = {block.ident(): "purple" for block in cfg.blocks \
                if block.tac_ops[-1].opcode == opcodes.SUICIDE}
    color_dict = {**returns, **stops, **throws, **suicides}
    nx.set_node_attributes(G, "color", color_dict)
    write_dot(G, out_filename)
