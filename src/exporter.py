"""exporter.py: abstract classes for exporting decompiler state"""

import abc
import csv
import os

import cfg
import opcodes
import patterns
import tac_cfg
import memtypes


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
  Writes logical relations of the given TAC CFG to local directory.

  Args:
    cfg: the graph to be written to logical relations.
  """
  def __init__(self, cfg:tac_cfg.TACGraph):
    """
    Generates .facts files of the given TAC CFG to local directory.

    Args:
      cfg: source TAC CFG to be exported to separate fact files.
    """
    super().__init__(cfg)

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

    self.__current_block = None
    """
    Previously visited TACOp.
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
    self.__current_block = block

  def visit_TACOp(self, op):
    """
    Visit a TACOp in a BasicBlock of the CFG.
    """

    if isinstance(op, tac_cfg.TACAssignOp):
      var_name = self.__current_block.ident() + ":"
      if isinstance(op.lhs, memtypes.Variable):
        var_name += op.lhs.name
      else:
        var_name += str(op.lhs)

      # Memory assignments are not considered as 'variable definitions'
      if op.opcode not in [opcodes.SLOAD, opcodes.MLOAD, opcodes.SSTORE,
                           opcodes.MSTORE, opcodes.MSTORE8]:
        # Generate variable definition relations (defined.facts)
        self.defined.append((hex(op.pc), var_name))

      # TODO: Add notion of blockchain and local memory
      # Generate variable write relations (write.facts)
      self.writes.append((hex(op.pc), var_name))

    for arg in op.args:
      # Only include variable reads; ignore constants
      if isinstance(arg, tac_cfg.TACArg) and not arg.value.is_const:
        arg_name = self.__current_block.ident() + ":" + arg.value.name
        # Generate variable read relations (read.facts)
        self.reads.append((hex(op.pc), arg_name))

  def export(self, output_dir:str="", dominators:bool=False):
    if output_dir != "":
      os.makedirs(output_dir, exist_ok=True)

    def generate(filename, entries):
      path = os.path.join(output_dir, filename)

      with open(path, 'w') as f:
        writer = csv.writer(f, delimiter='\t', lineterminator='\n')
        for e in entries:
          writer.writerow(e)

    # Write a mapping from operation addresses to corresponding opcode names,
    # as well as a mapping from operation addresses to the block they inhabit.
    ops = []
    block_nums = []
    for block in self.source.blocks:
      for op in block.tac_ops:
        ops.append((hex(op.pc), op.opcode.name))
        block_nums.append((hex(op.pc), block.ident()))
    generate("op.facts", ops)
    generate("block.facts", block_nums)

    # Write out the collection of edges between instructions (not basic blocks).
    edges = [(hex(h.pc), hex(t.pc))
             for h, t in self.source.op_edge_list()]
    generate("edge.facts", edges)

    # Entry points
    entry_ops = [(hex(b.tac_ops[0].pc),)
                 for b in self.source.blocks if len(b.preds) == 0]
    generate("entry.facts", entry_ops)

    # Exit points
    exit_points = [(hex(op.pc),) for op in self.source.terminal_ops]
    generate("exit.facts", exit_points)

    # Mapping from operation addresses to variable names defined there.
    generate("defined.facts", self.defined)

    # Mapping from operation addresses to variables read there.
    generate("read.facts", self.reads)

    # Mapping from operation addresses to variables written there.
    generate("write.facts", self.writes)

    if dominators:
      pairs = sorted([(k, i) for k, v
                      in self.source.dominators(op_edges=True).items()
                      for i in v])
      generate("dom.facts", pairs)

      pairs = sorted(self.source.immediate_dominators(op_edges=True).items())
      generate("imdom.facts", pairs)

      pairs = sorted([(k, i) for k, v
                      in self.source.dominators(post=True,
                                                op_edges=True).items()
                      for i in v])
      generate("pdom.facts", pairs)

      pairs = sorted(self.source.immediate_dominators(post=True,
                                                      op_edges=True).items())
      generate("impdom.facts", pairs)


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

    Certain blocks will have coloured outlines:
      Green: contains a RETURN operation;
      Blue: contains a STOP operation;
      Red: contains a THROW or THROWI operation;
      Purple: contains a SUICIDE operation;

    A node with a red fill indicates that its stack size is large.

    Args:
      out_filename: path to the file where dot output should be written.
                    If the file extension is a supported image format,
                    attempt to generate an image using the `dot` program,
                    if it is in the user's `$PATH`.
    """
    import networkx as nx
    import os

    cfg = self.source

    G = cfg.nx_graph()

    # Colour-code the graph.
    returns = {block.ident(): "green" for block in cfg.blocks
               if block.last_op.opcode == opcodes.RETURN}
    stops = {block.ident(): "blue" for block in cfg.blocks
             if block.last_op.opcode == opcodes.STOP}
    throws = {block.ident(): "red" for block in cfg.blocks
             if block.last_op.opcode in [opcodes.THROW, opcodes.THROWI]}
    suicides = {block.ident(): "purple" for block in cfg.blocks
                if block.last_op.opcode == opcodes.SUICIDE}
    color_dict = {**returns, **stops, **throws, **suicides}
    nx.set_node_attributes(G, "color", color_dict)
    filldict = {b.ident(): "white" if len(b.entry_stack) <= 20 else "red"
                for b in cfg.blocks}
    nx.set_node_attributes(G, "fillcolor", filldict)
    nx.set_node_attributes(G, "style", "filled")

    # Annotate each node with its basic block's internal data for later display
    # if rendered in html.
    nx.set_node_attributes(G, "id", {block.ident(): block.ident()
                                     for block in cfg.blocks})
    block_strings = {}
    for block in cfg.blocks:
      block_string = str(block)
      def_site_string = "\n\nDef sites:\n"
      for v in block.entry_stack.value:
        def_site_string += str(v) \
                           + ": {" \
                           + ", ".join(str(d) for d in v.def_sites) \
                           + "}\n"
      block_strings[block.ident()] = block_string + def_site_string
    nx.set_node_attributes(G, "tooltip", block_strings)

    # Write non-dot files using pydot and Graphviz
    if "." in out_filename and not out_filename.endswith(".dot"):
      pdG = nx.nx_pydot.to_pydot(G)
      extension = out_filename.split(".")[-1]

      # If we're producing an html file, write a temporary svg to build it from
      # and then delete it.
      if extension == "html":
        import pagify as p
        tmpname = out_filename + ".svg.tmp"
        pdG.write(tmpname, format="svg")
        p.pagify(tmpname, out_filename)
        os.remove(tmpname)
      else:
        pdG.write(out_filename, format=extension)

    # Otherwise, write a regular dot file using pydot
    else:
      if out_filename == "":
        out_filename = "cfg.dot"
      nx.nx_pydot.write_dot(G, out_filename)
