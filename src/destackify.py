"destackify.py: Destackifier converts basic blocks to Three-Address Code."

import typing

import opcodes
import cfglib
import tac


class Destackifier:
  """Converts EVMBasicBlocks into corresponding TAC operation sequences.

  Most instructions get mapped over directly, except:
      POP: generates no TAC op, but pops the symbolic stack;
      PUSH: generates a CONST TAC assignment operation;
      DUP, SWAP: these simply permute the symbolic stack, generate no ops;
      LOG0 ... LOG4: all translated to a generic LOG instruction
  """

  def __fresh_init(self) -> None:
    """Reinitialise all structures in preparation for converting a block."""

    # A sequence of three-address operations
    self.ops = []

    # The symbolic variable stack we'll be operating on.
    self.stack = []

    # The number of TAC variables we've assigned,
    # in order to produce unique identifiers. Typically the same as
    # the number of items pushed to the stack.
    self.stack_vars = 0

    # The depth we've eaten into the external stack. Incremented whenever
    # we pop and the main stack is empty.
    self.extern_pops = 0

  def __new_var(self) -> tac.Variable:
    """Construct and return a new variable with the next free identifier."""
    var = tac.Variable("V{}".format(self.stack_vars))
    self.stack_vars += 1
    return var

  def __pop_extern(self) -> tac.Variable:
    """Generate and return the next variable from the external stack."""
    var = tac.Variable("S{}".format(self.extern_pops))
    self.extern_pops += 1
    return var

  def __pop(self) -> tac.Variable:
    """
    Pop an item off our symbolic stack if one exists, otherwise
    generate an external stack variable.
    """
    if len(self.stack):
      return self.stack.pop()
    else:
      return self.__pop_extern()

  def __pop_many(self, n:int) -> typing.List[tac.Variable]:
    """
    Pop and return n items from the stack.
    First-popped elements inhabit low indices.
    """
    return [self.__pop() for _ in range(n)]

  def __push(self, element:tac.Variable) -> None:
    """Push an element to the stack."""
    self.stack.append(element)

  def __push_many(self, elements:typing.List[tac.Variable]) -> None:
    """
    Push a sequence of elements in the stack.
    Low index elements are pushed first.
    """

    for element in elements:
      self.__push(element)

  def __dup(self, n:int) -> None:
    """Place a copy of stack[n-1] on the top of the stack."""
    items = self.__pop_many(n)
    duplicated = [items[-1]] + items
    self.__push_many(reversed(duplicated))

  def __swap(self, n:int) -> None:
    """Swap stack[0] with stack[n]."""
    items = self.__pop_many(n)
    swapped = [items[-1]] + items[1:-1] + [items[0]]
    self.__push_many(reversed(swapped))

  def convert_block(self, block:cfglib.EVMBasicBlock) -> tac.TACBlock:
    """
    Given a EVMBasicBlock, convert its instructions to Three-Address Code.
    Return the converted sequence of operations,
    the final state of the stack,
    and the number of items that have been removed from the external stack.
    """
    self.__fresh_init()

    for line in block.lines:
      self.__handle_line(line)

    entry = block.lines[0].pc if len(block.lines) > 0 else -1
    exit = block.lines[-1].pc + block.lines[-1].opcode.push_len() \
           if len(block.lines) > 0 else -1

    new_block = tac.TACBlock(entry, exit, self.ops, self.stack, self.extern_pops)
    for op in self.ops:
      op.block = new_block
    return new_block

  def __handle_line(self, line:cfglib.EVMOp) -> None:
    """
    Convert a line to its corresponding instruction, if there is one,
    and manipulate the stack in any needful way.
    """

    if line.opcode.is_swap():
      self.__swap(line.opcode.pop)
    elif line.opcode.is_dup():
      self.__dup(line.opcode.pop)
    elif line.opcode == opcodes.POP:
      self.__pop()
    else:
      self.__gen_instruction(line)

  def __gen_instruction(self, line:cfglib.EVMOp) -> None:
    """
    Given a line, generate its corresponding TAC operation,
    append it to the op sequence, and push any generated
    variables to the stack.
    """

    inst = None
    # All instructions that push anything push exactly
    # one word to the stack. Assign that symbolic variable here.
    var = self.__new_var() if line.opcode.push == 1 else None

    # Generate the appropriate TAC operation.
    # Special cases first, followed by the fallback to generic instructions.
    if line.opcode.is_push():
      inst = tac.TACAssignOp(var, opcodes.CONST, [tac.Constant(line.value)],
                         line.pc, print_name=False)
    elif line.opcode.is_log():
      inst = tac.TACOp(opcodes.LOG, self.__pop_many(line.opcode.pop), line.pc)
    elif line.opcode == opcodes.MLOAD:
      inst = tac.TACAssignOp(var, line.opcode, [tac.MLoc(self.__pop())],
                         line.pc, print_name=False)
    elif line.opcode == opcodes.MSTORE:
      args = self.__pop_many(2)
      inst = tac.TACAssignOp(tac.MLoc(args[0]), line.opcode, args[1:],
                         line.pc, print_name=False)
    elif line.opcode == opcodes.MSTORE8:
      args = self.__pop_many(2)
      inst = tac.TACAssignOp(tac.MLocByte(args[0]), line.opcode, args[1:],
                         line.pc, print_name=False)
    elif line.opcode == opcodes.SLOAD:
      inst = tac.TACAssignOp(var, line.opcode, [tac.SLoc(self.__pop())],
                         line.pc, print_name=False)
    elif line.opcode == opcodes.SSTORE:
      args = self.__pop_many(2)
      inst = tac.TACAssignOp(tac.SLoc(args[0]), line.opcode, args[1:],
                         line.pc, print_name=False)
    elif var is not None:
      inst = tac.TACAssignOp(var, line.opcode,
                         self.__pop_many(line.opcode.pop), line.pc)
    else:
      inst = tac.TACOp(line.opcode, self.__pop_many(line.opcode.pop), line.pc)

    # This var must only be pushed after the operation is performed.
    if var is not None:
      self.__push(var)
    self.ops.append(inst)

