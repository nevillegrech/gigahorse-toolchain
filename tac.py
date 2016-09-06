# tac.py: Definitions of Three-Address Code operations and related objects.

from typing import List
import destackify


class Variable:
  """A symbolic variable whose value is supposed to be 
  the result of some TAC operation. Its size is 32 bytes."""

  size = 32

  def __init__(self, ident:str):
    self.identifier = ident

  def __str__(self):
    return self.identifier

  def __repr__(self):
    return "<{0} object {1}, {2}>".format(
      self.__class__.__name__,
      hex(id(self)),
      self.__str__()
    )

  def copy(self):
    return type(self)(self.identifier)

  def __eq__(self, other):
    return self.identifier == other.identifier

  def __hash__(self):
    return hash(self.identifier)

  def is_const(self):
    return False


class Constant(Variable):
  """A specialised variable whose value is a constant integer."""

  bits = 256
  max_val = 2**bits

  def __init__(self, value:int):
    self.value = value % self.max_val

  def __str__(self):
    return hex(self.value)

  def __eq__(self, other):
    return self.value == other.value

  def __hash__(self):
    return self.value

  def copy(self):
    return type(self)(self.value)

  def is_const(self):
    return True

  def signed(self):
    if self.value & (self.max_val - 1):
      return max_val - self.value

  # EVM arithmetic ops.
  @classmethod
  def ADD(cls, l, r):
    return cls((l.value + r.value))

  @classmethod
  def MUL(cls, l, r):
    return cls((l.value * r.value))

  @classmethod
  def SUB(cls, l, r):
    return cls((l.value - r.value))

  @classmethod
  def DIV(cls, l, r):
    return cls(0 if r.value == 0 else l.value // r.value)

  @classmethod
  def SDIV(cls, l, r):
    s_val, o_val = l.signed(), r.signed()
    sign = 1 if s_val * o_val >= 0 else -1
    return cls(0 if o_val == 0 else sign * (abs(s_val) // abs(o_val)))

  @classmethod
  def MOD(cls, l, r):
    return cls(0 if r.value == 0 else l.value % r.value)

  @classmethod
  def SMOD(cls, l, r):
    s_val, o_val = l.signed(), r.signed()
    sign = 1 if s_val >= 0 else -1
    return cls(0 if r.value == 0 else sign * (abs(s_val) % abs(o_val)))

  @classmethod
  def ADDMOD(cls, l, r, m):
    return cls(0 if m.value == 0 else (l.value + r.value) % m.value)

  @classmethod
  def MULMOD(cls, l, r, m):
    return cls(0 if m.value == 0 else (l.value * r.value) % m.value)

  @classmethod
  def EXP(cls, b, e):
    return cls(b.value ** e.value)

  @classmethod
  def SIGNEXTEND(cls, l, v):
    pos = 8(l.value + 1)
    mask = int("1"*(self.bits - pos) + "0"*pos, 2)
    val = 1 if (v.value & (1 << (pos - 1))) > 0 else 0

    return cls((v.value & mask) if val == 0 else (v.value | ~mask))

  @classmethod
  def LT(cls, l, r):
    return cls(1 if l.value < r.value else 0)

  @classmethod
  def GT(cls, l, r):
    return cls(1 if l.value < r.value else 0)

  @classmethod
  def SLT(cls, l, r):
    return cls(1 if l.signed() < r.signed() else 0)

  @classmethod
  def SGT(cls, l, r):
    return cls(1 if l.signed() > r.signed() else 0)

  @classmethod
  def EQ(cls, l, r):
    return cls(1 if l.value == r.value else 0)

  @classmethod
  def ISZERO(cls, v):
    return cls(1 if v.value == 0 else 0)

  @classmethod
  def AND(cls, l, r):
    return cls(l.value & r.value)

  @classmethod
  def OR(cls, l, r):
    return cls(l.value | r.value)

  @classmethod
  def XOR(cls, l, r):
    return cls(l.value ^ r.value)

  @classmethod
  def NOT(cls, v):
    return cls(~v.value)

  @classmethod
  def BYTE(cls, b, v):
    return cls((v >> (bits - b*8)) & 0xFF)


class Location:
  """A generic storage location."""

  def __init__(self, space_id:str, size:int, address:Variable):
    """Construct a location from the name of the space,
    and the size of the storage location in bytes."""
    self.space_id = space_id
    self.size = size
    self.address = address

  def __str__(self):
    return "{}[{}]".format(self.space_id, self.address)

  def __repr__(self):
    return "<{0} object {1}, {2}>".format(
      self.__class__.__name__,
      hex(id(self)),
      self.__str__()
    )

  def __eq__(self, other):
    return (self.space_id == other.space_id) \
           and (self.address == other.address) \
           and (self.size == other.size)

  def __hash__(self):
    return hash(self.space_id) ^ hash(self.size) ^ hash(self.address)

  def copy(self):
    return type(self)(self.space_id, self.size, self.address)

  def is_const(self):
    return False

class MLoc(Location):
  """A symbolic memory region 32 bytes in length."""
  def __init__(self, address:Variable):
    super().__init__("M", 32, address)

  def copy(self):
    return type(self)(self.address)


class MLoc8(Location):
  """ A symbolic one-byte cell from memory."""
  def __init__(self, address:Variable):
    super().__init__("M8", 1, address)

  def copy(self):
    return type(self)(self.address)


class SLoc(Location):
  """A symbolic one word static storage location."""
  def __init__(self, address:Variable):
    super().__init__("S", 32, address)

  def copy(self):
    return type(self)(self.address)

class TACOp:
  """
  A Three-Address Code operation.
  Each operation consists of a name, and a list of argument variables.
  """

  def __init__(self, name:str, args:List[Variable], \
               address:int, block=None):
    self.name = name
    self.args = args
    self.address = address
    self.block = block

  def __str__(self):
    return "{}: {} {}".format(hex(self.address), self.name, 
                " ".join([str(arg) for arg in self.args]))

  def __repr__(self):
    return "<{0} object {1}, {2}>".format(
      self.__class__.__name__,
      hex(id(self)),
      self.__str__()
    )
  
  def is_arithmetic(self) -> bool:
    return self.name in ["ADD", "MUL", "SUB", "DIV", "SDIV", "MOD", "SMOD",
                         "ADDMOD", "MULMOD", "EXP", "SIGNEXTEND", "LT", "GT",
                         "SLT", "SGT", "EQ", "ISZERO", "AND", "OR", "XOR",
                         "NOT", "BYTE"]

  def const_args(self):
    return all([arg.is_const() for arg in self.args])

  @classmethod
  def jump_to_throw(cls, op):
    if op.name not in ["JUMP", "JUMPI"]:
      return None
    elif op.name == "JUMP":
      return TACOp("THROW", [], op.address, op.block)
    elif op.name == "JUMPI":
      return TACOp("THROWI", [op.args[1]], op.address, op.block)


class TACAssignOp(TACOp):
  """
  A TAC operation that additionally takes a variable to which
  this operation's result is implicitly bound.
  """

  def __init__(self, lhs:Variable, name:str,
               args:List[Variable], address:int, print_name=True):
    super().__init__(name, args, address)
    self.lhs = lhs
    self.print_name = print_name

  def __str__(self):
    arglist = ([str(self.name)] if self.print_name else []) \
              + [str(arg) for arg in self.args]
    return "{}: {} = {}".format(hex(self.address), self.lhs, " ".join(arglist))


class TACBlock:
  def __init__(self, entry, exit, ops, stack_additions, stack_pops):
    self.entry = entry
    self.exit = exit
    self.ops = ops
    self.stack_additions = stack_additions
    self.stack_pops = stack_pops
    self.predecessors = []
    self.successors = []
    self.has_unresolved_jump = False

  def __str__(self):
    head = "Block [{}:{}]".format(hex(self.entry), hex(self.exit))
    op_seq = "\n".join(str(op) for op in self.ops)
    stack_state = "Stack pops: {}\nStack additions: {}".format(self.stack_pops,
                                                         self.stack_additions)
    pred = "Predecessors: [{}]".format(", ".join(hex(block.entry) \
                                               for block in self.predecessors))
    succ = "Successors: [{}]".format(", ".join(hex(block.entry) \
                                               for block in self.successors))
    unresolved = "Unresolved Jump" if self.has_unresolved_jump else ""
    return "\n".join([head, "---", op_seq, "---", \
                      stack_state, pred, succ, unresolved])

class TACCFG:
  def __init__(self, cfg):
    destack = destackify.Destackifier()

    # Convert all EVM blocks to TAC blocks.
    converted_map = {block: destack.convert_block(block) \
                     for block in cfg.blocks}

    # Determine which blocks have indeterminate jump destinations.
    for line in cfg.unresolved_jumps:
      converted_map[line.block].has_unresolved_jump = True

    # Connect all the edges.
    for block in converted_map:
      converted = converted_map[block]
      converted.predecessors = [converted_map[parent] \
                                for parent in block.parents]
      converted.successors = [converted_map[child] \
                              for child in block.children]

    self.blocks = converted_map.values()

  def edge_list(self):
    edges = []
    for src in self.blocks:
      for dest in src.successors:
        edges.append((src.entry, dest.entry))

    return edges

  def recalc_predecessors(self):
    for block in self.blocks:
      block.predecessors = []
    for block in self.blocks:
      for successor in block.successors:
        successor.predecessors.append(block)

  def recheck_jumps(self):
    for block in self.blocks:
      # TODO: Add new block containing a STOP if JUMPI fallthrough is from 
      # the very last instruction and no instruction is next.
      # (Maybe add this anyway as a common exit point during CFG construction?)
      jumpdest = None
      fallthrough = None
      final_op = block.ops[-1]
      invalid_jump = False
      unresolved = True

      if final_op.name == "JUMPI":
        dest = final_op.args[0]
        cond = final_op.args[1]

        # If the condition is constant, there is only one jump destination.
        if cond.is_const():
          # If the condition can never be true, ignore the jump dest.
          if cond.value == 0:
            fallthrough = self.get_block_by_address(final_op.address + 1)
            unresolved = False
          # If the condition is always true, 
          # check that the dest is constant and/or valid
          elif dest.is_const():
            if self.is_valid_jump_dest(dest.value):
              jumpdest = self.get_op_by_address(dest.value).block
            else:
              invalid_jump = True
            unresolved = False
          # Otherwise, the jump has not been resolved.
        elif dest.is_const():
          # We've already covered the case that both cond and dest are const
          # So only handle a variable condition
          unresolved = False
          fallthrough = self.get_block_by_address(final_op.address + 1)
          if self.is_valid_jump_dest(dest.value):
            jumpdest = self.get_op_by_address(dest.value).block
          else:
            invalid_jump = True

      elif final_op.name == "JUMP":
        dest = final_op.args[0]
        if dest.is_const():
          unresolved = False
          if self.is_valid_jump_dest(dest.value):
            jumpdest = self.get_op_by_address(dest.value).block
          else:
            invalid_jump = True

      else:
        unresolved = False

      # Block's jump went to an invalid location, replace the jump with a throw
      if invalid_jump:
        block.ops[-1] = TACOp.jump_to_throw(final_op)
      block.has_unresolved_jump = unresolved
      block.successors = [d for d in {jumpdest, fallthrough} if d is not None]

    # Having recalculated all the successors, hook up predecessors
    self.recalc_predecessors()

  def is_valid_jump_dest(self, address:int) -> bool:
    op = self.get_op_by_address(address)
    return (op is not None) and (op.name == "JUMPDEST")

  def get_block_by_address(self, address:int):
    for block in self.blocks:
      if block.entry <= address <= block.exit:
        return block
    return None

  def get_op_by_address(self, address:int):
    for block in self.blocks:
      for op in block.ops:
        if op.address == address:
          return op
    return None