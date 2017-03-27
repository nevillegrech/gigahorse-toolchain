import tac_cfg
import opcodes

import copy

# Note: best to wrap some of this into a function class (am working on)

class FunExtract():
  """
  A class for storing information about functions, still in progress
  """
  def __init__(self, tac:tac_cfg.TACGraph):
    self.internal_edges = {} # a mapping of internal edges, pred -> succs
    self.tac = tac

  def extract(self):
    """
    Extracts basic functions
    """
    for block in self.tac.blocks:
      if (self.__find_func_body(block)):
        body, preds = self.__find_func_body(block)
        self.__remove_path(body)
        end_mapping = self.__clone_path(body, preds)
        self.__hook_up_ends(body, end_mapping)
    return


  def __find_func_body(self, block):
    """
    Determines the boundaries of a function
    """
    # if there are multiple paths converging, this is a possible function start
    preds = list(block.preds)
    if (len(preds) <= 1):
      return False

    # do a BFS traversal and build the function body.
    # Traverse down levels until paths diverge again, the same amount as converged.
    # If this never happens assume program has ended and don't extract
    # note throws, multiple func ends not actually considered
    body = []
    queue = [block]
    cycle = False
    end = False # to check that the 'function' ends

    while (len(queue) > 0):
      cur_block = queue.pop(0)
      # possible func end checking
      if (len(cur_block.succs) == len(preds)
          and block.last_op.opcode in [opcodes.JUMP, opcodes.JUMPI]
          and cur_block.ident() != block.ident()):
        dests = block.last_op.args[0].value
        if (dests.is_finite or dests.def_sites.is_finite):
        # we have a function end! yay!
          end = True
          body.append(cur_block)
          break
      if cur_block not in body:
        body.append(cur_block)
        for b in cur_block.succs:
          queue.append(b)
      else:
        # Haven't considered this case yet
        cycle = True
        return False

    if end:
      return body, preds
    else:
      return False

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
        og = self.__get_by_ident(path, s)
        if og:
          for c in path_copies:
            self.tac.add_edge(c[i], c[path.index(og)])

    # hook up each pred to a path individually.
    end_mapping = {} # a mapping of pred to the end of its cloned path, used later
    for i, p in enumerate(preds):
      self.tac.add_edge(p, path_copies[i][0])
      end_mapping[p] = path_copies[i][-1]
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
        hooker = end_mapping[site.get_instruction().block]
        print(site.get_instruction().args[0].value)
        # extremely hacky thing below
        self.tac.add_edge(hooker, self.__get_by_address(str(site.get_instruction().args[0].value)))

  def __get_by_address(self, address):
    for block in self.tac.blocks:
      if hex(block.entry) == address:
        return block

  def __get_by_ident(self, path, ident):
    # ident should be unique - should I cover when it is not?
    for block in path:
      if block.ident() == ident:
        return block

  def export(self):
      """
      Returns the internal tac graph
      """
      return self.tac
