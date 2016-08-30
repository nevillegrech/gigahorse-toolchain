class MemLoc:
	"""
	A one byte cell from memory.
	"""

	def __init__(self, val):
		self.val = val

	def __str__(self):
		return "M[{}]".format(self.val)

	def __repr__(self):
		return "<{0} object {1}, {2}>".format(
			self.__class__.__name__,
			hex(id(self)),
			self.__str__()
		)

class StorageLoc:
	"""
	A one word static storage location.
	"""

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

class AssignOp(Op):
	name = "ASSIGNOP"
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

class OpConst(AssignOp):
	name = "CONST"
	def __init__(self, lhs, val):
		super().__init__(lhs, [val])

class OpAdd(AssignOp):
	name = "ADD"
	def __init__(self, lhs, lop, rop):
		super().__init__(lhs, [lop, rop])

class OpMul(AssignOp):
	name = "MUL"
	def __init__(self, lhs, lop, rop):
		super().__init__(lhs, [lop, rop])

class OpSub(AssignOp):
	name = "SUB"
	def __init__(self, lhs, lop, rop):
		super().__init__(lhs, [lop, rop])

class OpDiv(AssignOp):
	name = "DIV"
	def __init__(self, lhs, dividend, divisor):
		super().__init__(lhs, [dividend, divisor])

class OpSdiv(AssignOp):
	name = "SDIV"
	def __init__(self, lhs, dividend, divisor):
		super().__init__(lhs, [dividend, divisor])

class OpSmod(AssignOp):
	name = "SMOD"
	def __init__(self, lhs, value, modulus):
		super().__init__(lhs, [value, modulus])

class OpMod(AssignOp):
	name = "MOD"
	def __init__(self, lhs, value, modulus):
		super().__init__(lhs, [value, modulus])

class OpExp(AssignOp):
	name = "EXP"
	def __init__(self, lhs, base, exponent):
		super().__init__(lhs, [base, exponent])

class OpAddMod(AssignOp):
	name = "ADDMOD"
	def __init__(self, lhs, lop, rop, modulus):
		super().__init__(lhs, [lop, rop, modulus])

class OpMulMod(AssignOp):
	name = "MULMOD"
	def __init__(self, lhs, lop, rop, modulus):
		super().__init__(lhs, [lop, rop, modulus])

class OpSignExtend(AssignOp):
	name = "SIGNEXTEND"
	def __init__(self, lhs, size, value):
		super().__init__(lhs, [size, value])

class OpLt(AssignOp):
	name = "LT"
	def __init__(self, lhs, lop, rop):
		super().__init__(lhs, [lop, rop])

class OpGt(AssignOp):
	name = "GT"
	def __init__(self, lhs, lop, rop):
		super().__init__(lhs, [lop, rop])

class OpSlt(AssignOp):
	name = "SLT"
	def __init__(self, lhs, lop, rop):
		super().__init__(lhs, [lop, rop])

class OpSgt(AssignOp):
	name = "SGT"
	def __init__(self, lhs, lop, rop):
		super().__init__(lhs, [lop, rop])

class OpEq(AssignOp):
	name = "EQ"
	def __init__(self, lhs, lop, rop):
		super().__init__(lhs, [lop, rop])

class OpIsZero(AssignOp):
	name = "ISZERO"
	def __init__(self, lhs, op):
		super().__init__(lhs, [op])

class OpAnd(AssignOp):
	name = "AND"
	def __init__(self, lhs, lop, rop):
		super().__init__(lhs, [lop, rop])

class OpOr(AssignOp):
	name = "OR"
	def __init__(self, lhs, lop, rop):
		super().__init__(lhs, [lop, rop])

class OpXor(AssignOp):
	name = "XOR"
	def __init__(self, lhs, lop, rop):
		super().__init__(lhs, [lop, rop])

class OpNot(AssignOp):
	name = "NOT"
	def __init__(self, lhs, op):
		super().__init__(lhs, [op])

class OpByte(AssignOp):
	name = "BYTE"
	def __init__(self, lhs, index, val):
		super().__init__(lhs, [index, val])


class OpCodeCopy(Op):
	name = "CODECOPY"
	def __init__(self, mem_addr, code_addr, length):
		super().__init__([mem_addr, code_addr, length])


class OpStop(Op):
	name = "STOP"
	def __init__(self):
		super().__init__([])

class OpSHA3(AssignOp):
	name = "SHA3"
	def __init__(self, lhs, address, length):
		super().__init__(lhs, [address, length])

class OpAddress(AssignOp):
	name = "ADDRESS"
	def __init__(self, lhs):
		super().__init__(lhs, [])

class OpBalance(AssignOp):
	name = "BALANCE"
	def __init__(self, lhs, address):
		super().__init__(lhs, [address])

class OpOrigin(AssignOp):
	name = "ORIGIN"
	def __init__(self, lhs):
		super().__init__(lhs, [])

class OpCaller(AssignOp):
	name = "CALLER"
	def __init__(self, lhs):
		super().__init__(lhs, [])

class OpCallValue(AssignOp):
	name = "CALLVALUE"
	def __init__(self, lhs):
		super().__init__(lhs, [])

class OpCallValue(AssignOp):
	name = "CALLVALUE"
	def __init__(self, lhs):
		super().__init__(lhs, [])

class OpCallDataLoad(AssignOp):
	name = "CALLDATALOAD"
	def __init__(self, lhs, address):
		super().__init__(lhs, [address])

class OpCallDataSize(AssignOp):
	name = "CALLDATASIZE"
	def __init__(self, lhs):
		super().__init__(lhs)

class OpCallDataCopy(Op):
	name = "CALLDATACOPY"
	def __init__(self, mem_addr, data_addr, length):
		super().__init__([mem_addr, data_addr, length])

class OpGasPrice(AssignOp):
	name = "GASPRICE"
	def __init__(self, lhs):
		super().__init__(lhs, [])

class OpExtCodeSize(AssignOp):
	name = "CALLVALUE"
	def __init__(self, lhs):
		super().__init__(lhs, [])

class OpExtCodeCopy(Op):
	name = "EXTCODECOPY"
	def __init__(self, contract_addr, mem_addr, code_addr, length):
		super().__init__([contract_addr, mem_addr, code_addr, length])

class OpBlockHash(AssignOp):
	name = "BLOCKHASH"
	def __init__(self, lhs, blocknum):
		super().__init__(lhs, [blocknum])

class OpCoinBase(AssignOp):
	name = "COINBASE"
	def __init__(self, lhs):
		super().__init__(lhs, [])

class OpTimeStamp(AssignOp):
	name = "TIMESTAMP"
	def __init__(self, lhs):
		super().__init__(lhs, [])

class OpNumber(AssignOp):
	name = "NUMBER"
	def __init__(self, lhs):
		super().__init__(lhs, [])

class OpDifficulty(AssignOp):
	name = "DIFFICULTY"
	def __init__(self, lhs):
		super().__init__(lhs, [])

class OpGasLimit(AssignOp):
	name = "GASLIMIT"
	def __init__(self, lhs):
		super().__init__(lhs, [])

class OpMLoad(AssignOp):
	name = "MLOAD"
	def __init__(self, lhs, address):
		super().__init__(lhs, [MemLoc(address)])

class OpMStore(Op):
	name = "MSTORE"
	def __init__(self, address, val):
		super().__init__([address, val])

class OpMStore8(AssignOp):
	name = "MSTORE8"
	def __init__(self, address, val):
		super().__init__(MemLoc(address), [val])

class OpSLoad(AssignOp):
	name = "SLOAD"
	def __init__(self, lhs, address):
		super().__init__(lhs, [StorageLoc(address)])

class OpSStore(AssignOp):
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

class OpPC(AssignOp):
	name = "PC"
	def __init__(self, var):
		super().__init__(var, [])

class OpMSize(AssignOp):
	name = "MSIZE"
	def __init__(self, var):
		super().__init__(var, [])

class OpGas(AssignOp):
	name = "GAS"
	def __init__(self, var):
		super().__init__(var, [])

class OpLog(Op):
	name = "LOG"
	def __init__(self, address, length, topics):
		super().__init__([address, length] + topics)

class OpCreate(AssignOp):
	name = "CREATE"
	def __init__(self, lhs, value, address, length):
		super().__init__(lhs, [value, address, length])

class OpCall(AssignOp):
	name = "CALL"
	def __init__(self, lhs, gas, address, ether, input_addr, input_len, return_addr, return_len):
		super().__init__(lhs, [gas, address, ether, input_addr, input_len, return_addr, return_len])

class OpCallCode(AssignOp):
	name = "CALLCODE"
	def __init__(self, lhs, gas, address, ether, input_addr, input_len, return_addr, return_len):
		super().__init__(lhs, [gas, address, ether, input_addr, input_len, return_addr, return_len])

class OpReturn(Op):
	name = "RETURN"
	def __init__(self, mem_addr, length):
		super().__init__([mem_addr, length])

class OpDelegateCall(AssignOp):
	name = "DELEGATECALL"
	def __init__(self, lhs, gas, address, ether, input_addr, input_len, return_addr, return_len):
		super().__init__(lhs, [gas, address, ether, input_addr, input_len, return_addr, return_len])

class OpSuicide(Op):
	name = "SUICIDE"
	def __init__(self, address):
		super().__init__([address])
