"""exporter.py: abstract classes for exporting decompiler state"""

import abc
import csv
import os

import cfg
import memtypes
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


class CFGTsvExporter(Exporter, patterns.DynamicVisitor):
  """
  Generates .facts files of the given TAC CFG to local directory.

  Args:
    cfg: source TAC CFG to be exported to separate fact files.
  """
  def __init__(self, cfg:tac_cfg.TACGraph):
    super().__init__(cfg)
    self.ops = []
    """
    A list of pairs (op.pc, op.opcode), associating to each pc address the
    operation performed at that address.
    """

    self.edges = []
    """
    A list of edges between instructions defining a control flow graph.
    """

    self.defined = []
    """
    A list of pairs (op.pc, variable) that specify variable definition sites.
    """

    self.reads = []
    """
    A list of pairs (op.pc, variable) that specify all usage sites.
    """

    self.writes = []
    """
    A list of pairs (op.pc, variable) that specify all write locations.
    """

    self.block_nums = []
    """
    A list of pairs (op.pc, block.entry) that specify block numbers for each TACOp.
    """

    self.__prev_op = None
    """
    Previously visited TACOp.
    """

    self.__start_block = None
    """
    First BasicBlock visited, or None.
    """

    self.__end_block = None
    """
    Last BasicBlock visited, or None.
    """

    # Recursively visit the graph using a sorted traversal
    cfg.accept(self, generator=cfg.sorted_traversal())

  def visit_TACGraph(self, cfg):
    """
    Visit the TAC CFG root
    """
    pass

  def visit_TACBasicBlock(self, block):
    """
    Visit a TAC BasicBlock in the CFG
    """
    # Track the start and end blocks
    if self.__start_block is None:
      self.__start_block = block
    self.__end_block = block

    # Add edges from predecessor exits to this blocks's entry
    for pred in block.preds:
      # Generating edge.facts
      self.edges.append((hex(pred.tac_ops[-1].pc), hex(block.tac_ops[0].pc)))

  def visit_TACOp(self, op):
    """
    Visit a TACOp in a BasicBlock of the CFG.
    """
    # Add edges between TACOps (generate edge.facts)
    if self.__prev_op != None:
      # Generating edge relations (edge.facts)
      self.edges.append((hex(self.__prev_op.pc), hex(op.pc)))
    self.__prev_op = op

    # Generate opcode relations (op.facts)
    self.ops.append((hex(op.pc), op.opcode))

    # Generate opcode to basic block relations (block.facts)
    self.block_nums.append((hex(op.pc), hex(op.block.entry)))

    if isinstance(op, tac_cfg.TACAssignOp):
      # Memory assignments are not considered as 'variable definitions'
      if not op.opcode in [opcodes.SLOAD, opcodes.MLOAD]:
        # Generate variable definition relations (defined.facts)
        self.defined.append((hex(op.pc), op.lhs))

      # TODO: Add notion of blockchain and local memory
      # Generate variable write relations (write.facts)
      self.writes.append((hex(op.pc), op.lhs))

    for arg in op.args:
      # Only include variable reads; ignore constants
      if isinstance(arg, tac_cfg.TACArg) and not arg.value.is_const:
        # Generate variable read relations (read.facts)
        self.reads.append((hex(op.pc), arg))

  def export(self, output_dir:str=""):
    """
    Export the CFG to separate fact files.

    ``op.facts``
      (program counter, operation) pairs
    ``defined.facts``
      variable definition locations
    ``read.facts``
      var/loc use locations
    ``write.facts``
      var/loc write locations
    ``edge.facts``
      instruction-level CFG edges
    ``start.facts``
      the first location of the CFG
    ``end.facts``
      the last location of the CFG

    Args:
      output_dir: the output directory where fact files should be written.
      Will be created recursively if it doesn't exist.
    """
    # Create the target directory.
    if output_dir != "":
      os.makedirs(output_dir, exist_ok=True)

    def generate(filename, entries):
      path = os.path.join(output_dir, filename)

      with open(path, 'w') as f:
        writer = csv.writer(f, delimiter='\t', lineterminator='\n')
        for e in entries:
          writer.writerow(e)

    generate("op.facts", self.ops)
    generate("defined.facts", self.defined)
    generate("read.facts", self.reads)
    generate("write.facts", self.writes)
    generate("edge.facts", self.edges)
    generate("block.facts", self.block_nums)

    # Retrieve sorted list of blocks based on program counter
    # Note: Start and End are currently singletons
    # TODO -- Update starts and ends to be based on function boundaries
    start_fact = [hex(b.entry) for b in (self.__start_block,) if b is not None]
    end_fact = [hex(b.exit) for b in (self.__end_block,) if b is not None]
    generate("start.facts", [start_fact])
    generate("end.facts", [end_fact])

class CFGStringExporter(Exporter, patterns.DynamicVisitor):
  """
  Prints a textual representation of the given CFG to stdout.

  Args:
    cfg: source CFG to be printed.
    ordered: if True (default), print BasicBlocks in order of entry.
  """

  __BLOCK_SEP = "\n\n================================\n\n"

  def __init__(self, cfg:cfg.ControlFlowGraph, ordered:bool=True):
    super().__init__(cfg)
    self.ordered = ordered
    self.blocks = []
    self.source.accept(self)

  def visit_ControlFlowGraph(self, cfg):
    """
    Visit the CFG root
    """
    pass

  def visit_BasicBlock(self, block):
    """
    Visit a BasicBlock in the CFG
    """
    self.blocks.append((block.entry, str(block)))

  def export(self):
    """
    Print a textual representation of the input CFG to stdout.
    """
    if self.ordered:
      self.blocks.sort(key=lambda n: n[0])
    return self.__BLOCK_SEP.join(n[1] for n in self.blocks)


class CFGDotExporter(Exporter):
  """
  Generates a dot file for drawing a pretty picture of the given CFG.

  Args:
    cfg: source CFG to be exported to dot format.
  """
  def __init__(self, cfg:cfg.ControlFlowGraph):
    super().__init__(cfg)

  def export(self, out_filename:str="cfg.dot"):
    """
    Export the CFG to a dot file.

    Args:
      out_filename: path to the file where dot output should be written.
                    If the file extension is a supported image format,
                    attempt to generate an image using the `dot` program,
                    if it is in the user's `$PATH`.
    """
    import networkx as nx
    import os

    cfg = self.source

    G = nx.DiGraph()
    G.add_nodes_from(b.ident() for b in cfg.blocks)
    G.add_edges_from((p.ident(), s.ident()) for p, s in cfg.edge_list())
    G.add_edges_from((block.ident(), "?") for block in cfg.blocks
                     if block.has_unresolved_jump)

    returns = {block.ident(): "green" for block in cfg.blocks
               if block.tac_ops[-1].opcode == opcodes.RETURN}
    stops = {block.ident(): "blue" for block in cfg.blocks
             if block.tac_ops[-1].opcode == opcodes.STOP}
    throws = {block.ident(): "red" for block in cfg.blocks
             if block.tac_ops[-1].opcode in [opcodes.THROW, opcodes.THROWI]}
    suicides = {block.ident(): "purple" for block in cfg.blocks
                if block.tac_ops[-1].opcode == opcodes.SUICIDE}
    color_dict = {**returns, **stops, **throws, **suicides}
    nx.set_node_attributes(G, "color", color_dict)
    nx.set_node_attributes(G, "fillcolor", "white")
    nx.set_node_attributes(G, "style", "filled")
    nx.set_node_attributes(G, "id", {block.ident(): block.ident() for block in cfg.blocks})
    nx.set_node_attributes(G, "tooltip", {block.ident(): str(block) for block in cfg.blocks})

    # Write non-dot files using pydot and Graphviz
    if "." in out_filename and not out_filename.endswith(".dot"):
      extension = out_filename.split(".")[-1]
      pdG = nx.nx_pydot.to_pydot(G)
      pdG.write(out_filename, format=extension)
    # Otherwise, write a regular dot file using pydot
    else:
      nx.nx_pydot.write_dot(G, out_filename)
