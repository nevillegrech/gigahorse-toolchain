"""tac.py: Definitions of Three-Address Code operations and related
objects."""

import typing
import opcodes

class Variable:
  """A symbolic variable whose value is supposed to be
  the result of some TAC operation. Its size is 32 bytes."""

  SIZE = 32
  """Variables are 32 bytes in size."""

  CARDINALITY = 2**(SIZE * 8)
  """
  The number of distinct values representable by this variable.
  The maximum integer representable by this Variable is then CARDINALITY - 1.
  """

  def __init__(self, ident:str):
    """
    Args:
      ident: the name that uniquely identifies this variable.
    """
    self.ident = ident

  def __str__(self):
    return self.ident

  def __repr__(self):
    return "<{0} object {1}, {2}>".format(
      self.__class__.__name__,
      hex(id(self)),
      self.__str__()
    )

  def __eq__(self, other):
    return self.ident == other.ident

  # This needs to be a hashable type, in order to be used as a dict key;
  # Defining __eq__ requires us to redefine __hash__.
  def __hash__(self):
    return hash(self.ident)

  def is_const(self) -> bool:
    """
    True if this variable is an instance of Constant.
    Neater and more meaningful than using isinstance().
    """
    return False


class Constant(Variable):
  """A specialised variable whose value is a constant integer."""

  def __init__(self, value:int):
    self.value = value % self.CARDINALITY

  def __str__(self):
    return hex(self.value)

  def __eq__(self, other):
    return self.value == other.value

  # This needs to be a hashable type, in order to be used as a dict key;
  # Defining __eq__ requires us to redefine __hash__.
  def __hash__(self):
    return self.value

  def is_const(self) -> bool:
    """True if this Variable is a Constant."""
    return True

  def twos_compl(self) -> int:
    """
    Return the signed two's complement interpretation of this constant's value.
    """
    if self.value & (self.CARDINALITY - 1):
      return self.CARDINALITY - self.value


  # EVM arithmetic operations.
  # Each takes in two Constant arguments, and returns a new Constant
  # whose value is the result of applying the operation to the argument values.
  # For comparison operators, "True" and "False" are represented by Constants
  # with the value 1 and 0 respectively.

  @classmethod
  def ADD(cls, l: 'Constant', r: 'Constant') -> 'Constant':
    """Return the sum of the inputs."""
    return cls((l.value + r.value))

  @classmethod
  def MUL(cls, l: 'Constant', r: 'Constant') -> 'Constant':
    """Return the product of the inputs."""
    return cls((l.value * r.value))

  @classmethod
  def SUB(cls, l: 'Constant', r: 'Constant') -> 'Constant':
    """Return the difference of the inputs."""
    return cls((l.value - r.value))

  @classmethod
  def DIV(cls, l: 'Constant', r: 'Constant') -> 'Constant':
    """Return the quotient of the inputs."""
    return cls(0 if r.value == 0 else l.value // r.value)

  @classmethod
  def SDIV(cls, l: 'Constant', r: 'Constant') -> 'Constant':
    """Return the signed quotient of the inputs."""
    l_val, r_val = l.twos_compl(), r.twos_compl()
    sign = 1 if l_val * r_val >= 0 else -1
    return cls(0 if r_val == 0 else sign * (abs(l_val) // abs(r_val)))

  @classmethod
  def MOD(cls, v: 'Constant', m: 'Constant') -> 'Constant':
    """Modulo operator."""
    return cls(0 if m.value == 0 else v.value % m.value)

  @classmethod
  def SMOD(cls, v: 'Constant', m: 'Constant') -> 'Constant':
    """Signed modulo operator. The output takes the sign of v."""
    v_val, m_val = v.twos_compl(), m.twos_compl()
    sign = 1 if v_val >= 0 else -1
    return cls(0 if m.value == 0 else sign * (abs(v_val) % abs(m_val)))

  @classmethod
  def ADDMOD(cls, l: 'Constant', r: 'Constant', m: 'Constant') -> 'Constant':
    """Modular addition: return (l + r) modulo m."""
    return cls(0 if m.value == 0 else (l.value + r.value) % m.value)

  @classmethod
  def MULMOD(cls, l: 'Constant', r: 'Constant', m: 'Constant') -> 'Constant':
    """Modular multiplication: return (l * r) modulo m."""
    return cls(0 if m.value == 0 else (l.value * r.value) % m.value)

  @classmethod
  def EXP(cls, b: 'Constant', e: 'Constant') -> 'Constant':
    """Exponentiation: return b to the power of e."""
    return cls(b.value ** e.value)

  @classmethod
  def SIGNEXTEND(cls, b: 'Constant', v: 'Constant') -> 'Constant':
    """
    Return v, but with the high bit of its b'th byte extended all the way
    to the most significant bit of the output.
    """
    pos = 8 * (b.value + 1)
    mask = int("1"*((self.SIZE * 8) - pos) + "0"*pos, 2)
    val = 1 if (v.value & (1 << (pos - 1))) > 0 else 0

    return cls((v.value & mask) if val == 0 else (v.value | ~mask))

  @classmethod
  def LT(cls, l: 'Constant', r: 'Constant') -> 'Constant':
    """Less-than comparison."""
    return cls(1 if l.value < r.value else 0)

  @classmethod
  def GT(cls, l: 'Constant', r: 'Constant') -> 'Constant':
    """Greater-than comparison."""
    return cls(1 if l.value > r.value else 0)

  @classmethod
  def SLT(cls, l: 'Constant', r: 'Constant') -> 'Constant':
    """Signed less-than comparison."""
    return cls(1 if l.twos_compl() < r.twos_compl() else 0)

  @classmethod
  def SGT(cls, l: 'Constant', r: 'Constant') -> 'Constant':
    """Signed greater-than comparison."""
    return cls(1 if l.twos_compl() > r.twos_compl() else 0)

  @classmethod
  def EQ(cls, l: 'Constant', r: 'Constant') -> 'Constant':
    """Equality comparison."""
    return cls(1 if l.value == r.value else 0)

  @classmethod
  def ISZERO(cls, v: 'Constant') -> 'Constant':
    """1 if the input is zero, 0 otherwise."""
    return cls(1 if v.value == 0 else 0)

  @classmethod
  def AND(cls, l: 'Constant', r: 'Constant') -> 'Constant':
    """Bitwise AND."""
    return cls(l.value & r.value)

  @classmethod
  def OR(cls, l: 'Constant', r: 'Constant') -> 'Constant':
    """Bitwise OR."""
    return cls(l.value | r.value)

  @classmethod
  def XOR(cls, l: 'Constant', r: 'Constant') -> 'Constant':
    """Bitwise XOR."""
    return cls(l.value ^ r.value)

  @classmethod
  def NOT(cls, v: 'Constant') -> 'Constant':
    """Bitwise NOT."""
    return cls(~v.value)

  @classmethod
  def BYTE(cls, b: 'Constant', v: 'Constant') -> 'Constant':
    """Return the b'th byte of v."""
    return cls((v >> ((self.SIZE - b)*8)) & 0xFF)


class Location:
  """A generic storage location."""

  def __init__(self, space_id:str, size:int, address:Variable):
    """
    Construct a location from the name of the space,
    and the size of the storage location in bytes.

    Args:
      space_id: The identifier of an address space.
      size: Size of this location in bytes.
      address: Either a variable or a constant indicating the location.
    """
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

  # This needs to be a hashable type, in order to be used as a dict key;
  # Defining __eq__ requires us to redefine __hash__.
  def __hash__(self):
    return hash(self.space_id) ^ hash(self.size) ^ hash(self.address)

  def is_const(self) -> bool:
    """
    True if this variable is an instance of Constant.
    Neater and more meaningful than using isinstance().
    """
    return False

class MLoc(Location):
  """A symbolic memory region 32 bytes in length."""
  def __init__(self, address:Variable):
    super().__init__("M", 32, address)


class MLocByte(Location):
  """ A symbolic one-byte cell from memory."""
  def __init__(self, address:Variable):
    super().__init__("M1", 1, address)


class SLoc(Location):
  """A symbolic one word static storage location."""
  def __init__(self, address:Variable):
    super().__init__("S", 32, address)

class TACOp:
  """
  A Three-Address Code operation.
  Each operation consists of an opcode object defining its function, 
  a list of argument variables, and the unique program counter address 
  of the EVM instruction it was derived from.
  """

  def __init__(self, opcode:opcodes.OpCode, args:typing.List[Variable], \
               pc:int, block=None):
    """
    Args:
      opcode: the operation being performed.
      args: variables or constants that are operated upon.
      pc: the program counter at the corresponding instruction in the
          original bytecode.
      block: the block this operation belongs to.
    """
    self.opcode = opcode
    self.args = args
    self.pc = pc
    self.block = block

  def __str__(self):
    return "{}: {} {}".format(hex(self.pc), self.opcode,
                " ".join([str(arg) for arg in self.args]))

  def __repr__(self):
    return "<{0} object {1}, {2}>".format(
      self.__class__.__name__,
      hex(id(self)),
      self.__str__()
    )

  def const_args(self) -> bool:
    """True iff each of this operations arguments is a constant value."""
    return all([arg.is_const() for arg in self.args])

  @classmethod
  def convert_jump_to_throw(cls, op: 'TACOp') -> 'TACOp':
    """
    Given a jump, convert it to a throw, preserving the condition var if JUMPI.
    """
    if op.opcode not in [opcodes.JUMP, opcodes.JUMPI]:
      return None
    elif op.opcode == opcodes.JUMP:
      return cls(opcodes.THROW, [], op.pc, op.block)
    elif op.opcode == opcodes.JUMPI:
      return cls(opcodes.THROWI, [op.args[1]], op.pc, op.block)


class TACAssignOp(TACOp):
  """
  A TAC operation that additionally takes a variable to which
  this operation's result is implicitly bound.
  """

  def __init__(self, lhs:Variable, opcode:opcodes.OpCode,
               args:typing.List[Variable], pc:int, block=None,
               print_name=True):
    """
    Args:
      lhs: The variable that will receive the result of this operation.
      opcode: The operation being performed.
      args: Variables or constants that are operated upon.
      pc: The program counter at this instruction in the original bytecode.
      block: The block this operation belongs to.
      print_name: Some operations (e.g. CONST) don't need to print their
                  name in order to be readable.
    """
    super().__init__(opcode, args, pc, block)
    self.lhs = lhs
    self.print_name = print_name

  def __str__(self):
    arglist = ([str(self.opcode)] if self.print_name else []) \
              + [str(arg) for arg in self.args]
    return "{}: {} = {}".format(hex(self.pc), self.lhs, " ".join(arglist))


class TACBlock:
  def __init__(self, entry:int, exit:int, ops:typing.List[TACOp],
               stack_adds:typing.List[Variable], stack_pops:int):
    """
    Args:
      entry: The program counter of the first byte in the source EVM block
      exit: The pc of the last byte in the source EVM block
      ops: A sequence of TACOps whose execution is equivalent to the source EVM
      stack_adds: A sequence of new items inhabiting the top of stack after
                       this block is executed. The new head is last in sequence.
      stack_pops: the number of items removed from the stack over the course of
                  block execution.
      predecessors: A list of blocks that could branch to this block
      successors: A list of blocks that this one could branch to.
      has_unresolved_jump: True if the last instruction is a jump whose
                           destination is computed.

      Entry and exit variables should span the entire range of values enclosed
      in this block, taking care to note that the exit address may not be an
      instruction, but an argument of a POP.
      The range of pc values spanned by all blocks in the CFG should be a
      continuous range from 0 to the maximum value with no gaps between blocks.

      The stack_adds and stack_pops members together describe the change
      in the stack state as a result of running this block. That is, delete the
      top stack_pops items from the entry stack, then add the stack_additions
      items, to obtain the new stack.
    """

    self.entry = entry
    self.exit = exit
    self.ops = ops
    self.stack_adds = stack_adds
    self.stack_pops = stack_pops
    self.preds = []
    self.succs = []
    self.has_unresolved_jump = False

  def __str__(self):
    head = "Block [{}:{}]".format(hex(self.entry), hex(self.exit))
    op_seq = "\n".join(str(op) for op in self.ops)
    stack_state = "Stack pops: {}\nStack additions: [{}]".format( \
                              self.stack_pops, \
                              ", ".join([str(add) for add in self.stack_adds]))
    pred = "Predecessors: [{}]".format(", ".join(hex(block.entry) \
                                               for block in self.preds))
    succ = "Successors: [{}]".format(", ".join(hex(block.entry) \
                                               for block in self.succs))
    unresolved = "Unresolved Jump" if self.has_unresolved_jump else ""
    return "\n".join([head, "---", op_seq, "---", \
                      stack_state, pred, succ, unresolved])

class TacCfg:
  """
  A control flow graph holding Three-Address Code blocks and
  the edges between them.
  """

  def __init__(self, cfg):
    """
    Args:
      cfg: an EVM control flow graph to convert into three-address form.
    """
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
      converted.preds = [converted_map[parent] \
                                for parent in block.parents]
      converted.succs = [converted_map[child] \
                              for child in block.children]

    self.blocks = converted_map.values()

  def edge_list(self):
    """Return a list of all edges in the graph."""
    edges = []
    for src in self.blocks:
      for dest in src.succs:
        edges.append((src.entry, dest.entry))

    return edges

  def recalc_preds(self):
    """
    Given a cfg where block successor lists are populated,
    also populate the predecessor lists.
    """
    for block in self.blocks:
      block.preds = []
    for block in self.blocks:
      for successor in block.succs:
        successor.preds.append(block)

  def recheck_jumps(self):
    """
    Connect all edges in the graph that can be inferred given any constant
    values of jump destinations and conditions.
    Invalid jumps are replaced with THROW instructions.

    This is assumed to be performed after constant propagation and/or folding,
    since edges are deduced from constant-valued jumps.
    """
    for block in self.blocks:
      # TODO: Add new block containing a STOP if JUMPI fallthrough is from
      # the very last instruction and no instruction is next.
      # (Maybe add this anyway as a common exit point during CFG construction?)

      # TODO: Translate JUMPIs with constant conditions to JUMPS, or remove them

      jumpdest = None
      fallthrough = None
      final_op = block.ops[-1]
      invalid_jump = False
      unresolved = True

      if final_op.opcode == opcodes.JUMPI:
        dest = final_op.args[0]
        cond = final_op.args[1]

        # If the condition is constant, there is only one jump destination.
        if cond.is_const():
          # If the condition can never be true, ignore the jump dest.
          if cond.value == 0:
            fallthrough = self.get_block_by_pc(final_op.pc + 1)
            unresolved = False
          # If the condition is always true,
          # check that the dest is constant and/or valid
          elif dest.is_const():
            if self.is_valid_jump_dest(dest.value):
              jumpdest = self.get_op_by_pc(dest.value).block
            else:
              invalid_jump = True
            unresolved = False
          # Otherwise, the jump has not been resolved.
        elif dest.is_const():
          # We've already covered the case that both cond and dest are const
          # So only handle a variable condition
          unresolved = False
          fallthrough = self.get_block_by_pc(final_op.pc + 1)
          if self.is_valid_jump_dest(dest.value):
            jumpdest = self.get_op_by_pc(dest.value).block
          else:
            invalid_jump = True

      elif final_op.opcode == opcodes.JUMP:
        dest = final_op.args[0]
        if dest.is_const():
          unresolved = False
          if self.is_valid_jump_dest(dest.value):
            jumpdest = self.get_op_by_pc(dest.value).block
          else:
            invalid_jump = True

      else:
        unresolved = False

        # No terminating jump or a halt; fall through to next block.
        if not final_op.opcode.halts():
          fallthrough = self.get_block_by_pc(block.exit + 1)
          print(hex(block.entry))
          print(hex(fallthrough.entry) if fallthrough is not None else None)
          print()

      # Block's jump went to an invalid location, replace the jump with a throw
      if invalid_jump:
        block.ops[-1] = TACOp.convert_jump_to_throw(final_op)
      block.has_unresolved_jump = unresolved
      block.succs = [d for d in {jumpdest, fallthrough} if d is not None]
      print([hex(b.entry) for b in block.succs])

    # Having recalculated all the successors, hook up predecessors
    self.recalc_preds()

  def is_valid_jump_dest(self, pc:int) -> bool:
    """True iff the given program counter is a proper jumpdest."""
    op = self.get_op_by_pc(pc)
    return (op is not None) and (op.opcode == opcodes.JUMPDEST)

  def get_block_by_pc(self, pc:int):
    """Return the block whose span includes the given program counter value."""
    for block in self.blocks:
      if block.entry <= pc <= block.exit:
        return block
    return None

  def get_op_by_pc(self, pc:int):
    """Return the operation with the given program counter, if it exists."""
    for block in self.blocks:
      for op in block.ops:
        if op.pc == pc:
          return op
    return None

# We must import this here instead of at the top to resolve a circular
# dependency issue. Don't move this import. Beware dragons, etc.
import destackify
