# tacops.py: Definitions of all Three-Address Code operations, related functions, objects.

class Variable:
  """A symbolic variable whose value is supposed to be the result of some TAC operation."""

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

class MemLoc:
  """A symbolic one byte cell from memory."""

  def __init__(self, address):
    self.address = address

  def __str__(self):
    return "M[{}]".format(self.address)

  def __repr__(self):
    return "<{0} object {1}, {2}>".format(
      self.__class__.__name__,
      hex(id(self)),
      self.__str__()
    )

class StorageLoc:
  """A symbolic one word static storage location."""

  def __init__(self, val):
    self.val = val

  def __str__(self):
    return "S[{}]".format(self.val)

  def __repr__(self):
    return "<{0} object {1}, {2}>".format(
      self.__class__.__name__,
      hex(id(self)),
      self.__str__()
    )


class Op:
  """
  A Three-Address Code operation.
  Each operation consists of a name, and a list of arguments; typically Variables.
  """

  name = "OP"
  def __init__(self, args):
    self.args = args

  def __str__(self):
    return "{} {}".format(self.name, 
                " ".join([str(arg) for arg in self.args]))

  def __repr__(self):
    return "<{0} object {1}, {2}>".format(
      self.__class__.__name__,
      hex(id(self)),
      self.__str__()
    )

class OpAssign(Op):
  """
  A TAC operation that additionally takes a variable to which
  this operation's result is implicitly bound.
  """

  name = "OPASSIGN"
  def __init__(self, lhs, args):
    super().__init__(args)
    self.lhs = lhs

  def __str__(self):
    return "{} = {} {}".format(self.lhs, self.name,
                   " ".join([str(arg) for arg in self.args]))

  def __repr__(self):
    return "<{0} object {1}, {2}>".format(
      self.__class__.__name__,
      hex(id(self)),
      self.__str__()
    )

class OpConst(OpAssign):
  """Assignment of a constant value to a variable."""
  name = "CONST"
  def __init__(self, lhs, val):
    super().__init__(lhs, [val])

  def __str__(self):
    return "{} = {}".format(self.lhs, hex(self.args[0]))

class OpStop(Op):
  name = "STOP"
  def __init__(self):
    super().__init__([])

class OpAdd(OpAssign):
  name = "ADD"
  def __init__(self, lhs, lop, rop):
    super().__init__(lhs, [lop, rop])

class OpMul(OpAssign):
  name = "MUL"
  def __init__(self, lhs, lop, rop):
    super().__init__(lhs, [lop, rop])

class OpSub(OpAssign):
  name = "SUB"
  def __init__(self, lhs, lop, rop):
    super().__init__(lhs, [lop, rop])

class OpDiv(OpAssign):
  name = "DIV"
  def __init__(self, lhs, dividend, divisor):
    super().__init__(lhs, [dividend, divisor])

class OpSdiv(OpAssign):
  name = "SDIV"
  def __init__(self, lhs, dividend, divisor):
    super().__init__(lhs, [dividend, divisor])

class OpSmod(OpAssign):
  name = "SMOD"
  def __init__(self, lhs, value, modulus):
    super().__init__(lhs, [value, modulus])

class OpMod(OpAssign):
  name = "MOD"
  def __init__(self, lhs, value, modulus):
    super().__init__(lhs, [value, modulus])

class OpExp(OpAssign):
  name = "EXP"
  def __init__(self, lhs, base, exponent):
    super().__init__(lhs, [base, exponent])

class OpAddMod(OpAssign):
  name = "ADDMOD"
  def __init__(self, lhs, lop, rop, modulus):
    super().__init__(lhs, [lop, rop, modulus])

class OpMulMod(OpAssign):
  name = "MULMOD"
  def __init__(self, lhs, lop, rop, modulus):
    super().__init__(lhs, [lop, rop, modulus])

class OpSignExtend(OpAssign):
  name = "SIGNEXTEND"
  def __init__(self, lhs, size, value):
    super().__init__(lhs, [size, value])

class OpLt(OpAssign):
  name = "LT"
  def __init__(self, lhs, lop, rop):
    super().__init__(lhs, [lop, rop])

class OpGt(OpAssign):
  name = "GT"
  def __init__(self, lhs, lop, rop):
    super().__init__(lhs, [lop, rop])

class OpSlt(OpAssign):
  name = "SLT"
  def __init__(self, lhs, lop, rop):
    super().__init__(lhs, [lop, rop])

class OpSgt(OpAssign):
  name = "SGT"
  def __init__(self, lhs, lop, rop):
    super().__init__(lhs, [lop, rop])

class OpEq(OpAssign):
  name = "EQ"
  def __init__(self, lhs, lop, rop):
    super().__init__(lhs, [lop, rop])

class OpIsZero(OpAssign):
  name = "ISZERO"
  def __init__(self, lhs, op):
    super().__init__(lhs, [op])

class OpAnd(OpAssign):
  name = "AND"
  def __init__(self, lhs, lop, rop):
    super().__init__(lhs, [lop, rop])

class OpOr(OpAssign):
  name = "OR"
  def __init__(self, lhs, lop, rop):
    super().__init__(lhs, [lop, rop])

class OpXor(OpAssign):
  name = "XOR"
  def __init__(self, lhs, lop, rop):
    super().__init__(lhs, [lop, rop])

class OpNot(OpAssign):
  name = "NOT"
  def __init__(self, lhs, op):
    super().__init__(lhs, [op])

class OpByte(OpAssign):
  name = "BYTE"
  def __init__(self, lhs, index, val):
    super().__init__(lhs, [index, val])

class OpSHA3(OpAssign):
  name = "SHA3"
  def __init__(self, lhs, address, length):
    super().__init__(lhs, [address, length])

class OpAddress(OpAssign):
  name = "ADDRESS"
  def __init__(self, lhs):
    super().__init__(lhs, [])

class OpBalance(OpAssign):
  name = "BALANCE"
  def __init__(self, lhs, address):
    super().__init__(lhs, [address])

class OpOrigin(OpAssign):
  name = "ORIGIN"
  def __init__(self, lhs):
    super().__init__(lhs, [])

class OpCaller(OpAssign):
  name = "CALLER"
  def __init__(self, lhs):
    super().__init__(lhs, [])

class OpCallValue(OpAssign):
  name = "CALLVALUE"
  def __init__(self, lhs):
    super().__init__(lhs, [])

class OpCallValue(OpAssign):
  name = "CALLVALUE"
  def __init__(self, lhs):
    super().__init__(lhs, [])

class OpCallDataLoad(OpAssign):
  name = "CALLDATALOAD"
  def __init__(self, lhs, address):
    super().__init__(lhs, [address])

class OpCallDataSize(OpAssign):
  name = "CALLDATASIZE"
  def __init__(self, lhs):
    super().__init__(lhs)

class OpCallDataCopy(Op):
  name = "CALLDATACOPY"
  def __init__(self, mem_addr, data_addr, length):
    super().__init__([mem_addr, data_addr, length])

class OpCodeCopy(Op):
  name = "CODECOPY"
  def __init__(self, mem_addr, code_addr, length):
    super().__init__([mem_addr, code_addr, length])

class OpGasPrice(OpAssign):
  name = "GASPRICE"
  def __init__(self, lhs):
    super().__init__(lhs, [])

class OpExtCodeSize(OpAssign):
  name = "CALLVALUE"
  def __init__(self, lhs):
    super().__init__(lhs, [])

class OpExtCodeCopy(Op):
  name = "EXTCODECOPY"
  def __init__(self, contract_addr, mem_addr, code_addr, length):
    super().__init__([contract_addr, mem_addr, code_addr, length])

class OpBlockHash(OpAssign):
  name = "BLOCKHASH"
  def __init__(self, lhs, blocknum):
    super().__init__(lhs, [blocknum])

class OpCoinBase(OpAssign):
  name = "COINBASE"
  def __init__(self, lhs):
    super().__init__(lhs, [])

class OpTimeStamp(OpAssign):
  name = "TIMESTAMP"
  def __init__(self, lhs):
    super().__init__(lhs, [])

class OpNumber(OpAssign):
  name = "NUMBER"
  def __init__(self, lhs):
    super().__init__(lhs, [])

class OpDifficulty(OpAssign):
  name = "DIFFICULTY"
  def __init__(self, lhs):
    super().__init__(lhs, [])

class OpGasLimit(OpAssign):
  name = "GASLIMIT"
  def __init__(self, lhs):
    super().__init__(lhs, [])

# MLoad, MStore, SLoad, SStore operations have their own address spaces.
class OpMLoad(OpAssign):
  name = "MLOAD"
  def __init__(self, lhs, address):
    super().__init__(lhs, [MemLoc(address)])

class OpMStore(Op):
  name = "MSTORE"
  def __init__(self, address, val):
    super().__init__([address, val])

class OpMStore8(OpAssign):
  name = "MSTORE8"
  def __init__(self, address, val):
    super().__init__(MemLoc(address), [val])

class OpSLoad(OpAssign):
  name = "SLOAD"
  def __init__(self, lhs, address):
    super().__init__(lhs, [StorageLoc(address)])

class OpSStore(OpAssign):
  name = "SSTORE"
  def __init__(self, address, val):
    super().__init__(StorageLoc(address), [val])

class OpJump(Op):
  name = "JUMP"
  def __init__(self, dest):
    super().__init__([dest])

class OpJumpI(Op):
  name = "JUMPI"
  def __init__(self, dest, condition):
    super().__init__([dest, condition])

class OpPC(OpAssign):
  name = "PC"
  def __init__(self, var):
    super().__init__(var, [])

class OpMSize(OpAssign):
  name = "MSIZE"
  def __init__(self, var):
    super().__init__(var, [])

class OpGas(OpAssign):
  name = "GAS"
  def __init__(self, var):
    super().__init__(var, [])

class OpLog(Op):
  name = "LOG"
  def __init__(self, address, length, topics):
    super().__init__([address, length] + topics)

class OpCreate(OpAssign):
  name = "CREATE"
  def __init__(self, lhs, value, address, length):
    super().__init__(lhs, [value, address, length])

class OpCall(OpAssign):
  name = "CALL"
  def __init__(self, lhs, gas, address, ether, input_addr, input_len, return_addr, return_len):
    super().__init__(lhs, [gas, address, ether, input_addr, input_len, return_addr, return_len])

class OpCallCode(OpAssign):
  name = "CALLCODE"
  def __init__(self, lhs, gas, address, ether, input_addr, input_len, return_addr, return_len):
    super().__init__(lhs, [gas, address, ether, input_addr, input_len, return_addr, return_len])

class OpReturn(Op):
  name = "RETURN"
  def __init__(self, mem_addr, length):
    super().__init__([mem_addr, length])

class OpDelegateCall(OpAssign):
  name = "DELEGATECALL"
  def __init__(self, lhs, gas, address, ether, input_addr, input_len, return_addr, return_len):
    super().__init__(lhs, [gas, address, ether, input_addr, input_len, return_addr, return_len])

class OpSuicide(Op):
  name = "SUICIDE"
  def __init__(self, address):
    super().__init__([address])