"""exporter.py: abstract classes for exporting decompiler state"""

import abc

import cfg
import patterns

class CFGExporter(patterns.Visitor):
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
