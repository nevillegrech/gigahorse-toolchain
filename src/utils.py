"""utils.py: misc. functions used by other Python files in this project"""

def listdict_add(ldict:dict, key:object, val:object):
  """Adds a given value (val) to the list in a given list-valued dictionary
  (ldict) for the given key"""
  if key in ldict:
    ldict[key].append(val)
  else:
    ldict[key] = [val]

def cfg2dot(cfg, out_filename:str="cfg.dot"):
  """
  Outputs the given CFG in the Graphviz dot format, with output being saved
  in the file given as out_filename (or $PWD/cfg.dot by default).

  This function depends on the following extra Python libraries:
    - networkx
    - pydotplus
  """
  import networkx as nx
  from networkx.drawing.nx_pydot import write_dot
  G = nx.DiGraph()
  G.add_edges_from((hex(a), hex(b)) for a, b in cfg.edge_list())
  G.add_nodes_from(hex(b.lines[0].pc) for b in cfg.blocks)
  if len(cfg.unresolved_jumps) > 0:
    for l in cfg.unresolved_jumps:
      G.add_edge(hex(l.block.lines[0].pc), "?")
  write_dot(G, out_filename)


def taccfg2dot(cfg, out_filename:str="cfg.dot"):
  import networkx as nx
  from networkx.drawing.nx_pydot import write_dot
  G = nx.DiGraph()
  G.add_nodes_from(hex(b.entry) for b in cfg.blocks)
  G.add_edges_from((hex(a), hex(b)) for a, b in cfg.edge_list())
  G.add_edges_from((hex(block.entry), "?") for block in cfg.blocks \
                                            if block.has_unresolved_jump)

  returns = {hex(block.entry): "green" for block in cfg.blocks
             if block.ops[-1].name == "RETURN"}
  stops = {hex(block.entry): "blue" for block in cfg.blocks
             if block.ops[-1].name == "STOP"}
  throws = {hex(block.entry): "red" for block in cfg.blocks
             if block.ops[-1].name in ["THROW", "THROWI"]}
  suicides = {hex(block.entry): "purple" for block in cfg.blocks
               if block.ops[-1].name == "SUICIDE"}
  color_dict = {**returns, **stops, **throws, **suicides}
  nx.set_node_attributes(G, "color", color_dict)
  write_dot(G, out_filename)
