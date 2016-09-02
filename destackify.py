# destackify.py: Destackifier object for converting basic blocks to Three-Address Code.

from tacops import *
from opcodes import *

class Destackifier:
  """Converts BasicBlocks into corresponding TAC operation sequences."""

  def __init__(self):
    """
    Initialise a mapping from EVM opcodes to TAC operation constructors.
    This is in the constructor because the constructors manipulate the instance stack.
    """

    self.__fresh_init()

    # A mapping from EVM opcodes to TAC operation constructors.
    # Most instructions get mapped over directly, except:
    #     POP: generates no TAC op, but pops the symbolic stack;
    #     PUSH: generates a CONST TAC operation;
    #     DUP, SWAP: these simply permute the symbolic stack, generate no ops;
    #     JUMPDEST: discarded;
    #     LOG0 ... LOG4: all translated to a generic LOG instruction
    self.op_constructors = {
      STOP: lambda var: OpStop(),
      ADD: lambda var: OpAdd(var, *self.pop_many(2)),
      MUL: lambda var: OpMul(var, *self.pop_many(2)),
      SUB: lambda var: OpSub(var, *self.pop_many(2)),
      DIV: lambda var: OpDiv(var, *self.pop_many(2)),
      SDIV: lambda var: OpSdiv(var, *self.pop_many(2)),
      MOD: lambda var: OpMod(var, *self.pop_many(2)),
      SMOD: lambda var: OpSmod(var, *self.pop_many(2)),
      ADDMOD: lambda var: OpAddMod(var, *self.pop_many(3)),
      MULMOD: lambda var: OpMulMod(var, *self.pop_many(3)),
      EXP: lambda var: OpExp(var, *self.pop_many(2)),
      SIGNEXTEND: lambda var: OpSignExtend(var, *self.pop_many(2)),
      LT: lambda var: OpLt(var, *self.pop_many(2)),
      GT: lambda var: OpGt(var, *self.pop_many(2)),
      SLT: lambda var: OpSlt(var, *self.pop_many(2)),
      SGT: lambda var: OpSgt(var, *self.pop_many(2)),
      EQ: lambda var: OpEq(var, *self.pop_many(2)),
      ISZERO: lambda var: OpIsZero(var, self.pop()),
      AND: lambda var: OpAnd(var, *self.pop_many(2)),
      OR: lambda var: OpOr(var, *self.pop_many(2)),
      XOR: lambda var: OpXor(var, *self.pop_many(2)),
      NOT: lambda var: OpNot(var, *self.pop()),
      BYTE: lambda var: OpByte(var, *self.pop_many(2)),
      SHA3: lambda var: OpSHA3(var, *self.pop_many(2)),
      ADDRESS: lambda var: OpAddress(var),
      BALANCE: lambda var: OpBalance(var, self.pop()),
      ORIGIN: lambda var: OpOrigin(var),
      CALLER: lambda var: OpCaller(var),
      CALLVALUE: lambda var: OpCallValue(var),
      CALLDATALOAD: lambda var: OpCallDataLoad(var, self.pop()),
      CALLDATASIZE: lambda var: OpCallDataSize(var),
      CALLDATACOPY: lambda var: OpCallDataCopy(*self.pop_many(3)),
      CODECOPY: lambda var: OpCodeCopy(*self.pop_many(3)),
      GASPRICE: lambda var: OpGasPrice(var),
      EXTCODESIZE: lambda var: OpExtCodeSize(var),
      EXTCODECOPY: lambda var: OpExtCodeCopy(*self.pop_many(4)),
      BLOCKHASH: lambda var: OpBlockHash(var, self.pop()),
      COINBASE: lambda var: OpCoinBase(var),
      TIMESTAMP: lambda var: OpTimeStamp(var),
      NUMBER: lambda var: OpNumber(var),
      DIFFICULTY: lambda var: OpDifficulty(var),
      GASLIMIT: lambda var: OpGasLimit(var),
      MLOAD: lambda var: OpMLoad(var, self.pop()),
      MSTORE: lambda var: OpMStore(*self.pop_many(2)),
      MSTORE8: lambda var: OpMStore8(*self.pop_many(2)),
      SLOAD: lambda var: OpSLoad(var, self.pop()),
      SSTORE: lambda var: OpSStore(*self.pop_many(2)),
      JUMP: lambda var: OpJump(self.pop()),
      JUMPI: lambda var: OpJumpI(*self.pop_many(2)),
      PC: lambda var: OpPC(var),
      MSIZE: lambda var: OpMSize(var),
      GAS: lambda var: OpGas(var),
      CREATE: lambda var: OpCreate(var, *self.pop_many(3)),
      CALL: lambda var: OpCall(var, *self.pop_many(7)),
      CALLCODE: lambda var: OpCallCode(var, *self.pop_many(7)),
      RETURN: lambda var: OpReturn(*self.pop_many(2)),
      DELEGATECALL: lambda var: OpDelegateCall(var, *self.pop_many(7)),
      SUICIDE: lambda var: OpSuicide(self.pop())
    }


  def __fresh_init(self):
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


  def new_var(self):
    """Construct and return a new variable with the next free identifier."""
    var = Variable("V{}".format(self.stack_vars))
    self.stack_vars += 1
    return var

  def pop_extern(self):
    """Generate and return the next variable from the external stack."""
    var = Variable("S{}".format(self.extern_pops))
    self.extern_pops += 1
    return var

  def pop(self):
    """
    Pop an item off our symbolic stack if one exists, otherwise 
    generate an external stack variable.
    """
    if len(self.stack):
      return self.stack.pop()
    else:
      return self.pop_extern()

  def pop_many(self, n):
    """
    Pop and return n items from the stack.
    First-popped elements inhabit low indices.
    """
    return [self.pop() for _ in range(n)]

  def push(self, element):
    """Push an element to the stack."""
    self.stack.append(element)

  def push_many(self, elements):
    """
    Push a sequence of elements in the stack.
    Low index elements are pushed first.
    """

    for element in elements:
      self.push(element)

  def convert_block(self, block):
    """
    Given a BasicBlock, convert its instructions to Three-Address Code.
    Return the converted sequence of operations,
    the final state of the stack,
    and the number of items that have been removed from the external stack.
    """
    self.__fresh_init()

    for line in block.lines:
      self.handle_line(line)

    return (self.ops, self.stack, self.extern_pops)

  def dup(self, n):
    """Place a copy of stack[n-1] on the top of the stack."""
    items = self.pop_many(n)
    duplicated = [items[-1]] + items
    self.push_many(reversed(duplicated))

  def swap(self, n):
    """Swap stack[0] with stack[n]."""
    items = self.pop_many(n+1)
    swapped = [items[-1]] + items[1:-1] + [items[0]]
    self.push_many(reversed(swapped))

  def handle_line(self, line):
    """
    Convert a line to its corresponding instruction, if there is one,
    and manipulate the stack in any needful way.
    """

    if is_swap(line.opcode):
      self.swap(line.opcode.pop)
    elif is_dup(line.opcode):
      self.dup(line.opcode.pop)
    elif line.opcode == POP:
      self.pop()
    else:
      self.gen_instruction(line)

  def gen_instruction(self, line):
    """
    Given a line, generate its corresponding TAC operation,
    append it to the op sequence, and push any generated
    variables to the stack.
    """

    inst = None
    # All instructions that push anything push exactly
    # one word to the stack. Assign that symbolic variable here.
    var = self.new_var() if line.opcode.push >= 1 else None

    if is_push(line.opcode):
      inst = OpConst(var, line.value)
    elif is_log(line.opcode):
      inst = OpLog(*self.pop_many(2), self.pop_many(log_len(line.opcode)))
    elif line.opcode in self.op_constructors:
      inst = self.op_constructors[line.opcode](var)

    if inst is not None:
      self.ops.append(inst)
    if var is not None:
      self.push(var)