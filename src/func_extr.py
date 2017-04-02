import tac_cfg
import opcodes
import cfg

import copy

class FunExtract():
  """
  A class for storing information about functions, still in progress
  """
  def __init__(self, tac:tac_cfg.TACGraph):
    self.internal_edges = {} # a mapping of internal edges, pred -> succs
    self.tac = tac # the tac_cfg that this works on

  def extract(self):
    """
    Extracts basic functions
    """
    for block in self.tac.blocks:
      body, preds = self.__find_func_body(block)
      if body and preds:
        self.__remove_path(body)
        end_mapping = self.__clone_path(body, preds)
        self.__hook_up_ends(body, end_mapping)
    return


  def __find_func_body(self, block):
    """
    Determines the boundaries of a function - block is tested as beginning of function
    """
    # if there are multiple paths converging, this is a possible function start
    preds = list(block.preds)
    if (len(preds) <= 1):
      return None, None
    func_succs = [] # a list of what succs to look out for.
    for pre in preds:
      for op in pre.evm_ops:
        if op.opcode.is_push() and op.value != 0:
          # Check value. If not next block or prev block we have our dest block :)
          # Note: What about multiple jumps pushed in a block?
          # Stack checking is also a way to do this, but then need to figure out parameters.
          # Make sure you traverse from end of ops list to start to make sure?
          ref_block = self.tac.get_block_by_ident(hex(op.value));
          if ref_block and ref_block != block and ref_block not in block.succs: # no one-block functions
            func_succs.append(hex(op.value))
    if not func_succs: # Ensure that we did get pushed values!
      return None, None
    # do a BFS traversal and build the function body.
    # Traverse down levels until we hit a block that has the return addresses specified above
    body = []
    queue = [block]
    found_end = False
    while (len(queue) > 0):
      cur_block = queue.pop(0)
      end = False
      cur_succs = [b.ident() for b in cur_block.succs]
      if ((set(func_succs)).issubset(set(cur_succs))):
        end = True
        found_end = True
      if cur_block not in body:
        body.append(cur_block)
        if not end: #We don't append the succs of an end.
          for b in cur_block.succs:
            queue.append(b)

    if found_end:
      return body, preds
    return None, None

  def __remove_path(self, path):
    """
    remove a given path (ie function body) from a cfg.
    Returns a mapping of the node edges internally
    """
    for b in path:
      self.internal_edges[b] = [block.ident() for block in b.succs]
    for b in path:
      self.tac.remove_block(b)

    return

  def __clone_path(self, path, preds):
    """
    Clone the blocks of the path with internal connections intact.
    Hooks up with the correct predecessor
    Based off __split_copy_path function in tac_cfg
    """
    # copy the path the amount of times needed
    path_copies = [[copy.deepcopy(b) for b in path]
                    for _ in range(len(preds))]

    # Copy the nodes properly with internal_edges mapping
    for i, b in enumerate(path):
      og_succs = self.internal_edges[b]
      for s in og_succs:
        og = self.get_block_by_ident_from_path(path, s)
        if og:
          for c in path_copies:
            self.tac.add_edge(c[i], c[path.index(og)])

    # hook up each pred to a path individually.
    end_mapping = {} # a mapping of pred to the end of its cloned path, used later
    for i, p in enumerate(preds):
      self.tac.add_edge(p, path_copies[i][0]) # 0 is the first element in the path
      end_mapping[p] = path_copies[i][-1] # likewise the last element is -1,as the last element we appended
      for b in path_copies[i]:
        b.ident_suffix += "_" + p.ident()

    # Add the new paths to the graph.
    for c in path_copies:
      for b in c:
        self.tac.add_block(b)

    return end_mapping

  def __hook_up_ends(self, path, end_mapping):
    """
    Hooks up the end of each cloned path to the correct successor
    """
    last_block = path[-1]
    ends = self.internal_edges[path[-1]] # the succs of the last node in the path
    dests = list(last_block.last_op.args[0].value.values)
    for site in last_block.last_op.args[0].value.values.def_sites:
      if site.get_instruction().block in end_mapping:
        hooker = end_mapping[site.get_instruction().block]
        # extremely hacky thing below
        self.tac.add_edge(hooker, self.tac.get_block_by_ident(str(site.get_instruction().args[0].value)))

  def get_block_by_ident_from_path(self, path, ident):
    """Return the block with the specified identifier from in the given list of blocks, if it exists."""
    for block in path:
      if block.ident() == ident:
        return block
    return None


  def export(self):
    """
    Returns the internal tac graph
    """
    return self.tac
