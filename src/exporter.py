"""exporter.py: abstract classes for exporting decompiler state"""

import abc

import cfg
import patterns

class Exporter(abc.ABC):
  @abc.abstractmethod
  def export(self):
    """
    Abstract method which performs the final export using state collected
    during visitations.
    """

class CFGExporter(Exporter, patterns.Visitor):
  """
  Abstract base visitor for exporting CFGs.
  """
  @abc.abstractmethod
  def visit(self, cfg_node:cfg.CFGNode):
    """
    Abstract method which visits a given CFG node.

    Args:
      cfg_node: the CFG node to be visited.
    """

class PrintExporter(CFGExporter):
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
