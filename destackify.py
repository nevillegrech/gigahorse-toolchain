from cfglib import BasicBlock
from tacops import *
from opcodes import *

class Variable:
	def __init__(self, ident):
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

class Destackifier:
	def __init__(self):

		self.__fresh_init()

		self.op_actions = {
			MLOAD: lambda var: OpMLoad(var, MemLoc(self.pop())),
			MSTORE: lambda var: OpMStore(MemLoc(self.pop()), self.pop()),
			MSTORE8: lambda var: OpMStore8(MemLoc(self.pop()), self.pop()),
			SLOAD: lambda var: OpSLoad(var, StorageLoc(self.pop())),
			SSTORE: lambda var: OpSStore(StorageLoc(self.pop()), self.pop()),
			CODECOPY: lambda var: OpCodeCopy(*self.pop_many(3)),
			RETURN: lambda var: OpReturn(*self.pop_many(2)),
			STOP: lambda var: OpStop(),
			JUMP: lambda var: OpJump(self.pop()),
			JUMPI: lambda var: OpJumpI(*self.pop_many(2)),
			ADD: lambda var: OpAdd(var, *self.pop_many(2)),
			MUL: lambda var: OpMul(var, *self.pop_many(2)),
			SUB: lambda var: OpSub(var, *self.pop_many(2)),
			DIV: lambda var: OpDiv(var, *self.pop_many(2)),
			SDIV: lambda var: OpSdiv(var, *self.pop_many(2)),
			MOD: lambda var: OpMod(var, *self.pop_many(2)),
			SMOD: lambda var: OpSmod(var, *self.pop_many(2)),
			EXP: lambda var: OpExp(var, *self.pop_many(2)),
			SIGNEXTEND: lambda var: OpSignExtend(var, *self.pop_many(2)),
			ADDMOD: lambda var: OpAddMod(var, *self.pop_many(3)),
			MULMOD: lambda var: OpMulMod(var, *self.pop_many(3)),
			LT: lambda var: OpLt(var, *self.pop_many(2)),
			GT: lambda var: OpGt(var, *self.pop_many(2)),
			SLT: lambda var: OpSlt(var, *self.pop_many(2)),
			SGT: lambda var: OpSgt(var, *self.pop_many(2)),
			EQ: lambda var: OpEq(var, *self.pop_many(2)),
			ISZERO: lambda var: OpIsZero(var, self.pop()),
			AND: lambda var: OpAnd(var, *self.pop_many(2)),
			OR: lambda var: OpOr(var, *self.pop_many(2)),
			XOR: lambda var: OpXor(var, *self.pop_many(2)),
			NOT: lambda var: OpNot(var, *elf.pop()),
			BYTE: lambda var: OpByte(var, *self.pop_many(2)),
			CALLDATALOAD: lambda var: OpCallDataLoad(var, self.pop())
		}


	def __fresh_init(self):
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
		var = Variable("V{}".format(self.stack_vars))
		self.stack_vars += 1
		return var

	def pop_extern(self):
		"""
		Generate and return a variable from the external stack.
		"""

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

		res = []
		for _ in range(n):
			res.append(self.pop())

		return res

	def push(self, element):
		"""
		Push an element to the stack.
		"""

		self.stack.append(element)

	def push_many(self, elements):
		"""
		Push a sequence of elements in the stack.
		Low index elements are pushed first.
		"""

		for element in elements:
			self.push(element)


	def convert_block(self, block):
		self.__fresh_init()

		for line in block.lines:
			self.handle_line(line)

		return (self.ops, self.stack, self.extern_pops)

	def dup(self, n):
		"""
		Place a copy of stack[n-1] on the top of the stack.
		"""

		items = self.pop_many(n)
		duplicated = [items[-1]] + items
		self.push_many(reversed(duplicated))

	def swap(self, n):
		"""
		Swap stack[0] with stack[n].
		"""
		items = self.pop_many(n+1)
		swapped = [items[-1]] + items[1:-1] + [items[0]]
		self.push_many(reversed(swapped))

	def handle_line(self, line):
		if is_swap(line.opcode):
			self.swap(line.opcode.pop)
		elif is_dup(line.opcode):
			self.dup(line.opcode.pop)
		elif line.opcode == POP:
			self.pop()
		else:
			self.gen_instruction(line)


	def gen_instruction(self, line):
		inst = None
		var = self.new_var() if line.opcode.push >= 1 else None

		if is_push(line.opcode):
			inst = OpConst(var, line.value)
		elif line.opcode in self.op_actions:
			inst = self.op_actions[line.opcode](var)

		if inst is not None:
			self.ops.append(inst)
		if var is not None:
			self.push(var)








	












def destack_block(block:BasicBlock):
	d = Destackifier()






