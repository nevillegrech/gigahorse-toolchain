"""exporter.py: abstract classes for exporting decompiler state"""

import abc

import cfg
import tac_cfg
import patterns
import opcodes

class Exporter(abc.ABC):
  @abc.abstractmethod
  def export(self):
    """
    Abstract method which performs the final export using state collected
    during visitations.
    """


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
