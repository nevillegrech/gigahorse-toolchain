"""exporter.py: abstract classes for exporting decompiler state"""

import abc
import csv
import os

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

  def export(self, output_dir:str="", dominators:bool=False, out_opcodes=[]):
    """
    Args:
      output_dir: location to write the output to.
      dominators: output relations specifying dominators
      out_opcodes: a list of opcode names all occurences thereof to output,
                   with the names of all argument variables.
    """
    if output_dir != "":
      os.makedirs(output_dir, exist_ok=True)

    def generate(filename, entries):
      path = os.path.join(output_dir, filename)

      with open(path, 'w') as f:
        writer = csv.writer(f, delimiter='\t', lineterminator='\n')
        for e in entries:
          writer.writerow(e)

    # Write a mapping from operation addresses to corresponding opcode names;
    # a mapping from operation addresses to the block they inhabit;
    # any specified opcode listings.
    ops = []
    block_nums = []
    op_rels = {opcode: list() for opcode in out_opcodes}

    for block in self.source.blocks:
      for op in block.tac_ops:
        ops.append((hex(op.pc), op.opcode.name))
        block_nums.append((hex(op.pc), block.ident()))
        if op.opcode.name in out_opcodes:
          output_tuple = tuple([hex(op.pc)] +
                               [arg.value.name for arg in op.args])
          op_rels[op.opcode.name].append(output_tuple)

    generate("op.facts", ops)
    generate("block.facts", block_nums)
    for opcode in op_rels:
      generate("op_{}.facts".format(opcode), op_rels[opcode])

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

    # Mapping from variable names to the addresses they were defined at.
    define = []
    # Mapping from variable names to the addresses they were used at.
    use = []
    # Mapping from variable names to their possible values.
    value = []
    for block in self.source.blocks:
      for op in block.tac_ops:
        # If it's an assignment op, we have a def site
        if isinstance(op, tac_cfg.TACAssignOp):
          define.append((op.lhs.name, hex(op.pc)))

          # And we can also find its values here.
          if op.lhs.values.is_finite:
            for val in op.lhs.values:
              value.append((op.lhs.name, hex(val)))

        if op.opcode != opcodes.CONST:
          # The args constitute use sites.
          for arg in op.args:
            name = arg.value.name
            if not arg.value.def_sites.is_const:
              # Argument is a stack variable, and therefore needs to be
              # prepended with the block id.
              name = block.ident() + ":" + name
            use.append((name, hex(op.pc)))

      # Finally, note where each stack variable might have been defined,
      # and what values it can take on.
      # This includes some duplication for stack variables with multiple def
      # sites. This can be done marginally more efficiently.
      for var in block.entry_stack:
        if not var.def_sites.is_const and var.def_sites.is_finite:
          name = block.ident() + ":" + var.name
          for loc in var.def_sites:
            define.append((name, hex(loc.pc)))

          if var.values.is_finite:
            for val in var.values:
              value.append((name, hex(val)))

    generate("def.facts", define)
    generate("use.facts", use)
    generate("value.facts", value)

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
      Purple: contains a SELFDESTRUCT operation;
      Orange: contains a CALL, CALLCODE, or DELEGATECALL operation;
      Brown: contains a CREATE operation.

    A node with a red fill indicates that its stack size is large.

    Args:
      out_filename: path to the file where dot output should be written.
                    If the file extension is a supported image format,
                    attempt to generate an image using the `dot` program,
                    if it is in the user's `$PATH`.
    """
    import networkx as nx

    cfg = self.source

    G = cfg.nx_graph()

    callcodes = [opcodes.CALL, opcodes.CALLCODE, opcodes.DELEGATECALL]

    # Colour-code the graph.
    returns = {block.ident(): "green" for block in cfg.blocks
               if block.last_op.opcode == opcodes.RETURN}
    stops = {block.ident(): "blue" for block in cfg.blocks
             if block.last_op.opcode == opcodes.STOP}
    throws = {block.ident(): "red" for block in cfg.blocks
             if block.last_op.opcode in [opcodes.THROW, opcodes.THROWI]}
    suicides = {block.ident(): "purple" for block in cfg.blocks
                if block.last_op.opcode == opcodes.SELFDESTRUCT}
    creates = {block.ident(): "brown" for block in cfg.blocks
               if any(op.opcode == opcodes.CREATE for op in block.tac_ops)}
    calls = {block.ident(): "orange" for block in cfg.blocks
             if any(op.opcode in callcodes for op in block.tac_ops)}
    color_dict = {**returns, **stops, **throws, **suicides, **creates, **calls}
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
