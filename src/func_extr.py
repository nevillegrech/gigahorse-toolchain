"""func_extr.py: Classes for identifying and exporting functions in the control flow graph"""

import tac_cfg, memtypes
import typing as t

class FunExtract():
  """A class for extracting functions from an already generated TAC cfg."""

  def __init__(self, tac: tac_cfg.TACGraph):
    self.tac = tac  # the tac_cfg that this works on
    self.functions = []
    self.invoc_pairs = {} # a mapping of function invocation sites to their return addresses

  def extract(self) -> None:
    """Extracts private and public functions"""
    self.functions.extend(self.extract_private_funcs())
    self.functions.extend(self.extract_public_funcs())

  def export(self, mark: bool) -> str:
    """
    Returns a string representation of all the functions in the graph after extraction has been performed.
    
    Args:
      mark: if true, mark the function bodies in the control flow graph
      
    Returns:
      A string summary of all the functions in the control flow graph
    """
    ret_str = ""
    for i, func in enumerate(self.functions):
      ret_str += "Function " + str(i) + ":\n"
      ret_str += str(func) + "\n"

    if mark:
      for i, func in enumerate(self.functions):
       mark_body(func.body, i)
    return ret_str

  def extract_public_funcs(self) -> t.List['Function']:
    """Identifies public functions
    
    Returns:
      A list of of Function objects - public functions identified in the graph
    """
    # We follow the JUMPI chain down from the first CALLDATALOAD
    arr = [self.find_calldataload()]
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
      f = self.get_public_function(block)
      public_funcs.append(f)

    return public_funcs

  def find_calldataload(self) -> tac_cfg.TACBasicBlock:
    """
    Returns:
      The block with the first CALLDATALOAD opcode in the graph
    """
    block = self.tac.get_block_by_ident("0x0")
    for op in block.evm_ops:
      if op.opcode.name == "CALLDATALOAD":
        return block
    for succ in block.succs:
      for op in succ.evm_ops:
        if op.opcode.name == "CALLDATALOAD":
          return succ
    return None

  def get_public_function(self, block: tac_cfg.TACBasicBlock) -> t.List[tac_cfg.TACBasicBlock]:
    """
    Identifies the function starting with the given block
    
    Args:
      block: A BasicBlock to be used as the starting block for the function
      
    Returns:
      A list of BasicBlocks that consist of the body of the function
    """
    body = []
    queue = [block]
    end_block_candidates = []
    cur_block = block
    jump = False
    pre_jump_block = cur_block
    while len(queue) > 0:
      prevBlock = cur_block
      cur_block = queue.pop(0)
      # jump over private functions
      for f in self.functions:
        if cur_block in f.body and not jump:
          cur_block = self.__jump_to_next_loc(cur_block, prevBlock.exit_stack)
        if cur_block in f.body and jump:
          cur_block = self.__jump_to_next_loc(cur_block, pre_jump_block.exit_stack)
          jump = False
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
    # Get exit block
    for b in body:
      if len(b.succs) == 0:
        end_block_candidates.append(b)
    f = Function()
    f.body = body
    f.start_block = block
    f.end_block = end_block_candidates.pop()
    return f

  def __jump_to_next_loc(self, block: tac_cfg.TACBasicBlock, exit_stack: memtypes.VariableStack) -> tac_cfg.TACBasicBlock:
    """
    Helper method to jump over private functions during public function identification
    
    Args:
      block: The current block to be tested as being in the function body
      exit_stack: The stack of the previous block, or block before that after a previous jump over a function. This is
                  used to determine what the next block that is part of the public function should be.
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
      if not infunc and block not in self.invoc_pairs.keys() and block not in self.invoc_pairs.values() \
        and block.ident() in str(exit_stack):
        return block
      for succ in block.succs:
          if succ not in visited:
            queue.append(succ)
    return endBlock

  def extract_private_funcs(self) -> t.List[tac_cfg.TACBasicBlock]:
    """
    Extracts private functions
    
     Returns:
      A list of of Function objects - the private functions identified in the graph
    """
    # Get invocation site -> return block mappings
    start_blocks = []
    pair_list = []
    for block in reversed(self.tac.blocks):
      invoc_pairs = self.is_private_func_start(block)
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
            del start_blocks[i]
            modified = True
            break

    # Store invocation site - return pairs for later usage
    for d in pair_list:
      for key in d.keys():
        self.invoc_pairs[key] = d[key]

    # Find the Function body itself
    private_funcs = list()
    for i, block in enumerate(start_blocks):
      return_blocks = list(pair_list[i].values())
      f = self.find_func_body(block, return_blocks, pair_list)
      if not f or len(f.body) == 1:  # Can't have a function with 1 block in EVM
        continue
      if f is not None:
       private_funcs.append(f)
    return private_funcs

  def is_private_func_start(self, block: tac_cfg.TACBasicBlock) -> t.Dict[tac_cfg.TACBasicBlock, tac_cfg.TACBasicBlock]:
    """
    Determines the invocation and return points of the function beginning with the given block, if it exists.
    
    Args:
      block: a BasicBlock to be tested as the possible beginning of a function
      
    Returns:
      A mapping of invocation sites to return blocks of the function, if the given block is the start of a function. 
      None if the block is not the beginning of a function.
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

  def find_func_body(self, block: tac_cfg.TACBasicBlock, return_blocks: t.List[tac_cfg.TACBasicBlock], invoc_pairs: t.List[tac_cfg.TACBasicBlock]) -> 'Function':
    """
    Assuming the block is a definite function start, identifies all paths from start to end using BFS
    
    Args:
      block: the start block of a function
      return_blocks: the list of return blocks of the function
      invoc_pairs: a mapping of all other invocation and return point pairs to allow jumping over other functions
      
    Returns:
      A function object representing the function starting with the given block
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
      # We assume the end_block is the last block in the disasm from all candidates
      f.end_block = sorted(exit_blocks, key=lambda block: block.ident()).pop()
      f.succs = return_blocks
      f.preds = block.preds
      f.body = body
      return f
    return None

  def reachable(self, block: tac_cfg.TACBasicBlock, dests: t.List[tac_cfg.TACBasicBlock]) -> bool:
    """
    Determines if a block can reach any of the given destination blocks
    
    Args:
      block: Any block that is part of the tac_cfg the class was initialised with
      dests: A list of dests to check reachability with
    """
    if block in dests:
      return True
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

  def getCFG(self) -> tac_cfg.TACGraph:
    """
    Returns:
      The internal tac_cfg object
    """
    return self.tac

def mark_body(path: t.List[tac_cfg.TACBasicBlock], num: int) -> None:
  """
  Marks every block in the path with the given number. 
  """
  for block in path:
    block.ident_suffix += "_F" + str(num)

class Function:
  """
  A representation of a function with associated metadata
  """
  def __str__(self):
    entry_block = "Entry block: " + self.start_block.ident()
    if self.end_block is not None:
      exit_block = "Exit block: " + self.end_block.ident()
    else:
      exit_block = "Exit block: None identified"
    body = "Body: " + ", ".join(b.ident() for b in self.body)
    return "\n".join([entry_block, exit_block, body])


  def __init__(self):
    self.body = []
    self.start_block = None
    self.end_block = None
    self.mapping = {}  # a mapping of preds to succs of the function body.
