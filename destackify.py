# destackify.py: Destackifier object for converting basic blocks to Three-Address Code.

from tacops import *
from opcodes import *

class Destackifier:
  """Converts BasicBlocks into corresponding TAC operation sequences.

  Most instructions get mapped over directly, except:
      POP: generates no TAC op, but pops the symbolic stack;
      PUSH: generates a CONST TAC operation;
      DUP, SWAP: these simply permute the symbolic stack, generate no ops;
      LOG0 ... LOG4: all translated to a generic LOG instruction
  """

  def _fresh_init(self):
    """Reinitialise all structures in preparation for converting a new block."""

    # A sequence of three-address operations
    self.ops = []

    # The stack we'll be symbolically operating on.
    self.stack = []

    # The number of TAC variables we've assigned,
    # in order to produce unique identifiers. Typically the same as
    # the number of items pushed to the stack.
    self.stack_vars = 0

    # The depth we've eaten into the external stack. Incremented whenever
    # we pop and the main stack is empty.
    self.extern_pops = 0


  def _new_var(self):
    """Construct and return a new variable with the next free identifier."""
    var = Variable("V{}".format(self.stack_vars))
    self.stack_vars += 1
    return var

  def _pop_extern(self):
    """Generate and return the next variable from the external stack."""
    var = Variable("S{}".format(self.extern_pops))
    self.extern_pops += 1
    return var

  def _pop(self):
    """
    Pop an item off our symbolic stack if one exists, otherwise 
    generate an external stack variable.
    """
    if len(self.stack):
      return self.stack.pop()
    else:
      return self._pop_extern()

  def _pop_many(self, n):
    """
    Pop and return n items from the stack.
    First-popped elements inhabit low indices.
    """
    return [self._pop() for _ in range(n)]

  def _push(self, element):
    """Push an element to the stack."""
    self.stack.append(element)

  def _push_many(self, elements):
    """
    Push a sequence of elements in the stack.
    Low index elements are pushed first.
    """

    for element in elements:
      self._push(element)

  def convert_block(self, block):
    """
    Given a BasicBlock, convert its instructions to Three-Address Code.
    Return the converted sequence of operations,
    the final state of the stack,
    and the number of items that have been removed from the external stack.
    """
    self._fresh_init()

    for line in block.lines:
      self._handle_line(line)

    return (self.ops, self.stack, self.extern_pops)

  def _dup(self, n):
    """Place a copy of stack[n-1] on the top of the stack."""
    items = self._pop_many(n)
    duplicated = [items[-1]] + items
    self._push_many(reversed(duplicated))

  def _swap(self, n):
    """Swap stack[0] with stack[n]."""
    items = self._pop_many(n+1)
    swapped = [items[-1]] + items[1:-1] + [items[0]]
    self._push_many(reversed(swapped))

  def _handle_line(self, line):
    """
    Convert a line to its corresponding instruction, if there is one,
    and manipulate the stack in any needful way.
    """

    if is_swap(line.opcode):
      self._swap(line.opcode.pop)
    elif is_dup(line.opcode):
      self._dup(line.opcode.pop)
    elif line.opcode == POP:
      self._pop()
    else:
      self._gen_instruction(line)

  def _gen_instruction(self, line):
    """
    Given a line, generate its corresponding TAC operation,
    append it to the op sequence, and push any generated
    variables to the stack.
    """

    inst = None
    # All instructions that push anything push exactly
    # one word to the stack. Assign that symbolic variable here.
    var = self._new_var() if line.opcode.push == 1 else None
    
    # TODO: Work out the rules for MLOAD/MSTORE properly,
    # since stack items are words, while memory locations are bytes.

    if is_push(line.opcode):
      inst = TACAssignOp(var, "CONST", [line.value], print_name=False)
    elif is_log(line.opcode):
      inst = TACOp("LOG", self._pop_many(line.opcode.pop))
    elif line.opcode == MLOAD:
      inst = TACAssignOp(var, line.opcode.name, [MLoc(self._pop())], print_name=False)
    elif line.opcode == MSTORE:
      args = self._pop_many(2)
      inst = TACAssignOp(MLoc(args[0]), line.opcode.name, args[1:], print_name=False)
    elif line.opcode == MSTORE8:
      args = self._pop_many(2)
      inst = TACAssignOp(MLoc8(args[0]), line.opcode.name, args[1:], print_name=False)
    elif line.opcode == SLOAD:
      inst = TACAssignOp(var, SLOAD.name, [SLoc(self._pop())], print_name=False)
    elif line.opcode == SSTORE:
      args = self._pop_many(2)
      inst = TACAssignOp(SLoc(args[0]), line.opcode.name, args[1:])
    elif var is not None:
      inst = TACAssignOp(var, line.opcode.name, self._pop_many(line.opcode.pop))
    else:
      inst = TACOp(line.opcode.name, self._pop_many(line.opcode.pop))

    # This var must be pushed after the operation is performed.
    if var is not None:
      self._push(var)
    self.ops.append(inst)
    