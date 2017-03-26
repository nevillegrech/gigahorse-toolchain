import tac_cfg
import opcodes

import copy

# Note: best to wrap some of this into a function class (am working on)

# controlling function
def extract(tac):
  for block in tac.blocks:
    if (find_func_body(block)):
      body, preds = find_func_body(block)
      internal_edges = remove_path(body, tac)
      end_mapping = clone_path(body, preds, internal_edges, tac)
      hook_up_ends(tac, body, internal_edges, end_mapping)
  return tac


def find_func_body(block):
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
      # Haven't considered this case yet, need to think about it
      cycle = True
      return False

  if end:
    return body, preds
  else:
    return False

def remove_path(path, cfg):
  """
  remove a given path (ie function body) from a cfg.
  Returns a mapping of the node edges internally
  """
  internal_edges = {} # a mapping of internal edges, pred -> succs
  for b in path:
    internal_edges[b] = [block.ident() for block in b.succs]
  for b in path:
    cfg.remove_block(b)
  return internal_edges

def clone_path(path, preds, internal_edges, tac):
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
    og_succs = internal_edges[b]
    for s in og_succs:
      og = __get_by_ident(path, s)
      if og:
        for c in path_copies:
          tac.add_edge(c[i], c[path.index(og)])

  # hook up each pred to a path individually.
  end_mapping = {} # a mapping of pred to the end of its cloned path, used later
  for i, p in enumerate(preds):
    tac.add_edge(p, path_copies[i][0])
    end_mapping[p] = path_copies[i][-1]
    for b in path_copies[i]:
      b.ident_suffix += "_" + p.ident()

  # Add the new paths to the graph.
  for c in path_copies:
    for b in c:
      tac.add_block(b)

  return end_mapping

def hook_up_ends(tac, path, internal_edges, end_mapping):
  """
  Hooks up the end of each cloned path to the correct successor
  """
  last_block = path[-1]
  ends = internal_edges[path[-1]] # the succs of the last node in the path
  dests = list(last_block.last_op.args[0].value.values)
  for site in last_block.last_op.args[0].value.values.def_sites:
      hooker = end_mapping[site.get_instruction().block]
      print(site.get_instruction().args[0].value)
      # extremely hacky thing below
      tac.add_edge(hooker, __get_by_address(tac,
                                   str(site.get_instruction().args[0].value)))

def __get_by_address(tac, address):
  for block in tac.blocks:
    if hex(block.entry) == address:
      return block

def __get_by_ident(path, ident):
  # ident should be unique - should I cover when it is not?
  for block in path:
    if block.ident() == ident:
      return block
