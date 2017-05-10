import tac_cfg
from typing import List, Dict

class FunExtract():
  """
  A class for extracting functions from an already generated TAC cfg
  """
  def __init__(self, tac: tac_cfg.TACGraph):
    self.tac = tac  # the tac_cfg that this works on
    self.functions = []
    self.invoc_pairs = {} # a mapping of function invocation sites to their return addresses

  def extract(self) -> None:
    """
    Extracts private and public functions
    """
    self.extract_private_funcs()
    self.extract_public_funcs()
    for i, func in enumerate(self.functions):
      mark_body(func.body, i)

  def extract_public_funcs(self):
    """
    Identifies public functions
    """
    # We follow the JUMPI chain down from the first CALLDATALOAD
    arr = [self.find_calldataload(self.tac.get_block_by_ident("0x0"))]
    starts = []
    while len(arr) > 0:
      curblock = arr.pop(0)
      for succ in curblock.succs:
        found = False
        for op in reversed(succ.evm_ops):
          if op.opcode.name == "PUSH4":
            arr.append(succ)
            found = True
            break
        if not found:
          starts.append(succ)

    public_funcs = list()
    for block in starts:
      f = self.get_public_body(block)
      public_funcs.append(f)
      self.functions.append(f)

    return public_funcs

  def find_calldataload(self, block):
    """
    Finds the block with the first CALLDATALOAD opcode in the graph. 
    """
    for op in block.evm_ops:
      if op.opcode.name == "CALLDATALOAD":
        return block
    for succ in block.succs:
      for op in succ.evm_ops:
        if op.opcode.name == "CALLDATALOAD":
          return succ
    return None

  def get_public_body(self, block):
    """
    Identifies the function body starting with the given block using BFS
    """
    body = []
    queue = [block]
    cur_block = block
    jump = False
    pre_jump_block = cur_block
    while len(queue) > 0:
      prevBlock = cur_block
      cur_block = queue.pop(0)
      # 'Jump' over private functions
      for f in self.functions:
        if cur_block in f.body and not jump:
          cur_block = self.jump_to_next_loc(cur_block, prevBlock.exit_stack)
        if cur_block in f.body and jump:
          cur_block = self.jump_to_next_loc(cur_block, pre_jump_block.exit_stack)
          jump = False
      # Do we need to apply this multiple times for multiply nested functions?
      if cur_block in self.invoc_pairs:
        jump = True
        pre_jump_block = cur_block
        if cur_block not in body:
          body.append(cur_block)
        cur_block = self.invoc_pairs[cur_block]
      if cur_block not in body:
        body.append(cur_block)
        for b in cur_block.succs:
            queue.append(b)
    f = Function(body)
    f.start_block = block
    return f

  def jump_to_next_loc(self, block, exit_stack):
    """
    Helper method to jump over private functions
    """
    queue = [block]
    visited = [block]
    endBlock = None;
    while len(queue) > 0:
      block = queue.pop();
      if len(block.succs) == 0:
        endBlock = block
      visited.append(block)
      infunc = False
      for f in self.functions:
        if block in f.body:
          infunc = True
          break
      if not infunc and block not in self.invoc_pairs.keys() and block not in self.invoc_pairs.values() and block.ident() in str(exit_stack):
        return block
      for succ in block.succs:
          if succ not in visited:
            queue.append(succ)
    return endBlock

  def extract_private_funcs(self) -> None:
    """
    Extracts private functions
    """
    # Get invocation site -> return block mappings
    start_blocks = []
    pair_list = []
    for block in reversed(self.tac.blocks):
      invoc_pairs = self.find_private_func_start(block)
      if invoc_pairs:
        start_blocks.append(block)
        pair_list.append(invoc_pairs)

    # remove start blocks without any possible function body
    modified = True
    while modified:
      modified = False
      for i, entry in enumerate(pair_list):
        for pred in entry:
          succ = entry[pred]
          if not self.reachable(pred, [succ]):
            del entry[pred]
            modified = True
            break

    # Store invocation site - return pairs for later usage
    for d in pair_list:
      for key in d.keys():
        self.invoc_pairs[key] = d[key]
    # Find the Function body itself
    for i, block in enumerate(start_blocks):
      return_blocks = list(pair_list[i].values())
      f = self.find_func_body(block, return_blocks, pair_list)
      if not f or len(f.body) == 1:  # Can't have a function with 1 block in EVM
        continue
      if f is not None:
        self.functions.append(f)
    return

  def find_private_func_start(self, block: tac_cfg.TACBasicBlock) -> Dict[tac_cfg.TACBasicBlock, tac_cfg.TACBasicBlock]:
    """
    Determines the boundaries of a private function - block is tested as beginning of function. Returns a mapping of invocation 
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
          if ref_block is not None and val in list(pre.delta_stack):
            func_mapping[pre] = ref_block
            func_succs.append(ref_block)
            break
          params.append(val)
    if not func_succs or len(func_mapping) == 1:
      return None

    # We have our Start
    return func_mapping

  def find_func_body(self, block: tac_cfg.TACBasicBlock, return_blocks: List[tac_cfg.TACBasicBlock], invoc_pairs: List[tac_cfg.TACBasicBlock]) -> 'Function':
    """
    Assuming the block is a definite function start, identifies all paths from start to end using BFS
    """
    # Traverse down levels with BFS until we hit a block that has the return addresses specified above

    body = []
    queue = [block]
    end = False
    while len(queue) > 0:
      cur_block = queue.pop(0)
      for entry in invoc_pairs:  # When we call a function, we just jump to the return address
        if cur_block in entry:
          body.append(cur_block)
          cur_block = entry[cur_block]
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
      f.start_block = block
      poss_exit_blocks = [b.preds for b in return_blocks]
      exit_blocks = set(poss_exit_blocks[0])
      for preds in poss_exit_blocks:
        exit_blocks = exit_blocks & set(preds)
      f.exit_block = exit_blocks.pop()
      f.succs = return_blocks
      f.preds = block.preds
      f.body = body
      return f
    return None

  def reachable(self, block: tac_cfg.TACBasicBlock, dests: List[tac_cfg.TACBasicBlock]) -> bool:
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

  def export(self) -> tac_cfg.TACGraph:
    """
    Returns the internal tac graph
    """
    return self.tac


class Function:
  """
  A representation of a function with associated metadata
  """

  def __init__(self, body=[], mapping=None, params=None, start_block=None, end_block=None):
    self.body = body
    self.start_block = start_block
    self.end_block = end_block
    if mapping is not None:
      self.mapping = mapping  # a mapping of preds to succs of the function body.
    self.params = params

  def getparams(self) -> None:
    """
    Get arguments to function if we have not already retrieved them
    """
    self.params = []
    for pred in self.mapping:
      for val in list(pred.exit_stack):
        ref_block = self.tac.get_block_by_ident(str(val))
        if ref_block is not None:
          break
        self.params.append(val)


def mark_body(path: List[tac_cfg.TACBasicBlock], num: int) -> None:
  for block in path:
    block.ident_suffix += "_F" + str(num)
