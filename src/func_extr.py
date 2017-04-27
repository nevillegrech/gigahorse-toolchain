import tac_cfg

class FunExtract():
  """
  A class for extracting functions from an already generated TAC cfg
  """

  def __init__(self, tac: tac_cfg.TACGraph):
    self.internal_edges = {}  # a mapping of internal edges, pred -> succs
    self.tac = tac  # the tac_cfg that this works on

  def extract(self):
    """
    Extracts basic functions
    """
    func_count = 0
    start_blocks = []
    pair_list = []
    for block in reversed(self.tac.blocks):
      invoc_pairs = self.__find_func_start(block)
      if invoc_pairs:
        start_blocks.append(block)
        pair_list.append(invoc_pairs)

    # remove start blocks without any possible function body
    modified = True
    while modified:
      modified = False
      for i, dict in enumerate(pair_list):
        for pred in dict:
          succ = dict[pred]
          if not self.reachable(pred, [succ]):
            del dict[pred]
            modified = True
            break

    # Find the Function body itself
    for i, block in enumerate(start_blocks):
      preds = pair_list[i].keys()
      return_blocks = list(pair_list[i].values())
      f = self.find_func_body(block, return_blocks, pair_list)
      if not f or len(f.body) == 1:  # Can't have a function with 1 block in EVM
        continue
      if f:
        mark_body(f.body, ("F" + str(func_count)));
        func_count += 1
    return

  def __find_func_start(self, block):
    """
    Determines the boundaries of a function - block is tested as beginning of function. Returns a mapping of invocation 
    sites to return addresses if successful.
    """
    # if there are multiple paths converging, this is a possible function start
    preds = list(block.preds)
    if (len(preds) <= 1) or len(list(block.succs)) == 0:
      return None
    func_succs = []  # a list of what succs to look out for.
    func_mapping = {}  # mapping of pre -> end
    params = []  # list of parameters
    for pre in preds:
      if pre not in block.succs:
        # Check for at least 2 push opcodes and net stack gain
        pushCount = 0
        for evm_op in pre.evm_ops:
          if evm_op.opcode.is_push():
            pushCount += 1
        if pushCount <= 1:
          return None
        if len(pre.delta_stack) == 0:
          return None
        for val in list(pre.exit_stack):
          ref_block = self.tac.get_block_by_ident(str(val))
          if ref_block:
            func_mapping[pre] = ref_block
            func_succs.append(ref_block)
            break
          params.append(val)
    if not func_succs:  # Ensure that we did get pushed values!
      return None
    # We have our Start
    return func_mapping

  def find_func_body(self, block, return_blocks, invoc_list):
    """
    Assuming the block is a definite function start, identifies all paths from start to end
    """
    # do a BFS traversal and build the function body.
    # Traverse down levels until we hit a block that has the return addresses specified above
    body = []
    queue = [block]
    end = False
    while (len(queue) > 0):
      cur_block = queue.pop(0)
      for dict in invoc_list:  # When we call a function, we just jump to the return address
        if cur_block in dict:
          body.append(cur_block)
          cur_block = dict[cur_block]
      cur_succs = [b for b in cur_block.succs]
      if ((set(return_blocks)).issubset(set(cur_succs))):
        end = True
      if cur_block not in body and self.reachable(cur_block, return_blocks):
        body.append(cur_block)
        for b in cur_block.succs:
          if b not in return_blocks:
            queue.append(b)

    if end:
      f = Function()
      f.succs = return_blocks
      f.body = body
      return f
    return None

  def reachable(self, block, dests):
    """
    Determine if a block can reach any of the given destination blocks
    """
    queue = [block]
    traversed = []
    while queue:
      cur_block = queue.pop()
      traversed.append(cur_block)
      for b in dests:
        if b in cur_block.succs:
          return True
      for b in cur_block.succs:
        if b not in traversed:
          queue.append(b)
    return False

  def export(self):
    """
    Returns the internal tac graph
    """
    return self.tac


class Function:
  """
  A representation of a function with associated metadata
  """

  def __init__(self, body=None, mapping=None, params=None):
    if params is None:
      self.params = []
    else:
      self.params = params
    self.body = []
    if mapping is not None:
      self.mapping = mapping  # a mapping of preds to succs of the function body.
      self.preds = [b for b in mapping]
      self.succs = [mapping[b] for b in mapping]
      # Get all parameters if we have not gotten them yet.

  @classmethod
  def getparams(self) -> None:
    """
    Get arguments to function if we have not already retrieved them
    """
    self.params = []
    for pred in self.mapping:
      for val in list(pred.exit_stack):
        ref_block = self.tac.get_block_by_ident(str(val))
        if ref_block:
          break
        self.params.append(val)


def mark_body(path, num):
  for block in path:
    block.ident_suffix += "_" + str(num)
