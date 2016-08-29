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

class OpMLoad(AssignOp):
	name = "MLOAD"
	def __init__(self, lhs, memloc):
		super().__init__(lhs, [memloc])

class OpMStore(AssignOp):
	name = "MSTORE"
	def __init__(self, memloc, val):
		super().__init__(memloc, [val])

class OpMStore8(AssignOp):
	name = "MSTORE8"
	def __init__(self, memloc, val):
		super().__init__(memloc, [val])

class OpSLoad(AssignOp):
	name = "SLOAD"
	def __init__(self, lhs, storageloc):
		super().__init__(lhs, [storageloc])

class OpSStore(AssignOp):
	name = "SSTORE"
	def __init__(self, storageloc, val):
		super().__init__(storageloc, [val])


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

class OpCallDataLoad(AssignOp):
	name = "CALLDATALOAD"
	def __init__(self, lhs, address):
		super().__init__(lhs, [address])


class OpCodeCopy(Op):
	name = "CODECOPY"
	def __init__(self, mem_addr, code_addr, length):
		super().__init__([mem_addr, code_addr, length])


class OpReturn(Op):
	name = "RETURN"
	def __init__(self, mem_addr, length):
		super().__init__([mem_addr, length])

class OpJump(Op):
	name = "JUMP"
	def __init__(self, dest):
		super().__init__([dest])

class OpJumpI(Op):
	name = "JUMPI"
	def __init__(self, dest, condition):
		super().__init__([dest, condition])

class OpStop(Op):
	name = "STOP"
	def __init__(self):
		super().__init__([])

