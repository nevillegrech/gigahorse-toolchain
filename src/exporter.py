"""exporter.py: abstract classes for exporting decompiler state"""

import abc

import cfg
import opcodes
import patterns
import tac_cfg

class Exporter(abc.ABC):
  def __init__(self, source:object):
    """
    Args:
      source: object instance to be exported
    """
    self.source = source

  @abc.abstractmethod
  def export(self):
    """
    Exports the source object to an implementation-specific format.
    """


class CFGPrintExporter(Exporter, patterns.DynamicVisitor):
  def __init__(self, source:object, ordered:bool=True):
    super().__init__(source)
    self.ordered = ordered
    self.nodes = []
    self.source.accept(self)

  def visit_ControlFlowGraph(self, cfg):
    pass

  def visit_BasicBlock(self, node):
    self.nodes.append((node.entry, str(node)))

  def export(self):
    if self.ordered:
      self.nodes.sort(key=lambda n: n[0])
    for n in self.nodes:
      print(n[1])


class CFGDotExporter(Exporter):
  def __init__(self, cfg:cfg.ControlFlowGraph):
    self.cfg = cfg

  def export(self, out_filename:str="cfg.dot"):
    """From a CFG, generate a dotfile for drawing a pretty picture of it."""
    import networkx as nx
    from networkx.drawing.nx_pydot import write_dot
    G = nx.DiGraph()
    G.add_nodes_from(b.ident() for b in self.cfg.blocks)
    G.add_edges_from((p, s) for p, s in self.cfg.edge_list())
    G.add_edges_from((block.ident(), "?") for block in self.cfg.blocks \
                     if block.has_unresolved_jump)

    returns = {block.ident(): "green" for block in self.cfg.blocks \
               if block.tac_ops[-1].opcode == opcodes.RETURN}
    stops = {block.ident(): "blue" for block in self.cfg.blocks \
             if block.tac_ops[-1].opcode == opcodes.STOP}
    throws = {block.ident(): "red" for block in self.cfg.blocks \
             if block.tac_ops[-1].opcode in [opcodes.THROW, opcodes.THROWI]}
    suicides = {block.ident(): "purple" for block in self.cfg.blocks \
                if block.tac_ops[-1].opcode == opcodes.SUICIDE}
    color_dict = {**returns, **stops, **throws, **suicides}
    nx.set_node_attributes(G, "color", color_dict)
    write_dot(G, out_filename)
