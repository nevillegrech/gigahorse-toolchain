# BSD 3-Clause License
#
# Copyright (c) 2016, 2017, The University of Sydney. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the copyright holder nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""opcodes.py: Definitions of all EVM opcodes, and related utility functions with associated gas costs"""



class OpCode:
    """An EVM opcode."""

    def __init__(self, name:str, code:int, pop:int, push:int, gas:int):
        """
        Args:
          name (str): Human-readable opcode.
          code (int): The instruction byte itself.
          pop (int): The number of stack elements this op pops.
          push (int): The number of stack elements this op pushes.
          gas (int): The gas cost of this op. These costs come from appendix H of the Ethereum Yellow Paper (http://yellowpaper.io/).

        Note: The gas costs of some operations are dynamic depending on the data they are manipluating. We assume the lowest gas costs to determine an upper bound in gas costs.
        """
        self.name = name
        self.code = code
        self.pop = pop
        self.push = push
        self._gas = gas

    def stack_delta(self) -> int:
        """Return the net effect on the stack size of running this operation."""
        return self.push - self.pop

    def __str__(self) -> str:
        return self.name

    def __repr__(self) -> str:
        return "<{0} object {1}, {2}>".format(
            self.__class__.__name__,
            hex(id(self)),
            self.__str__()
        )

    def __eq__(self, other) -> bool:
        return self.code == other.code

    def __hash__(self) -> int:
        return self.code.__hash__()

    def gas(self) -> int:
        return self._gas

    def is_push(self) -> bool:
        """Predicate: opcode is a push operation."""
        return PUSH1.code <= self.code <= PUSH32.code

    def is_swap(self) -> bool:
        """Predicate: opcode is a swap operation."""
        return SWAP1.code <= self.code <= SWAP16.code

    def is_dup(self) -> bool:
        """Predicate: opcode is a dup operation."""
        return DUP1.code <= self.code <= DUP16.code

    def is_log(self) -> bool:
        """Predicate: opcode is a log operation."""
        return LOG0.code <= self.code <= LOG4.code

    def is_missing(self) -> bool:
        return self.code not in BYTECODES

    def is_invalid(self) -> bool:
        return (self.code == INVALID.code) or self.is_missing()

    def is_arithmetic(self) -> bool:
        """Predicate: opcode's result can be calculated from its inputs alone."""
        return (ADD.code <= self.code <= SIGNEXTEND.code) or \
               (LT.code <= self.code <= SAR.code)

    def is_memory(self) -> bool:
        """Predicate: opcode operates on memory"""
        return MLOAD.code <= self.code <= MSTORE8.code

    def is_storage(self) -> bool:
        """Predicate: opcode operates on storage ('the tape')"""
        return SLOAD.code <= self.code <= SSTORE.code

    def is_call(self) -> bool:
        """Predicate: opcode calls an external contract"""
        return self in (CALL, CALLCODE, DELEGATECALL, STATICCALL,)

    def alters_flow(self) -> bool:
        """Predicate: opcode alters EVM control flow."""
        return (self.code in (JUMP.code, JUMPI.code,)) or self.possibly_halts()
    
    def is_exception(self) -> bool:
        """Predicate: opcode causes the EVM to throw an exception."""
        return (self.code in (INVALID.code, REVERT.code)) \
                or self.is_invalid()

    def halts(self) -> bool:
        """Predicate: opcode causes the EVM to halt."""
        halt_codes = (
            STOP.code,
            RETURN.code,
            SELFDESTRUCT.code,
            REVERT.code,
        )
        return (self.code in halt_codes) or self.is_invalid()

    def possibly_halts(self) -> bool:
        """Predicate: opcode MAY cause the EVM to halt. (halts)"""
        return self.halts()

    def push_len(self) -> int:
        """Return the number of bytes the given PUSH instruction pushes."""
        return self.code - PUSH1.code + 1 if self.is_push() else 0

    def log_len(self) -> int:
        """Return the number of topics the given LOG instruction includes."""
        return self.code - LOG0.code if self.is_log() else 0

    def pop_words(self) -> int:
        return self.pop

    def push_words(self) -> int:
        return self.push

    def ord(self) -> int:
        return self.code

# Construct all EVM opcodes

# Arithmetic Ops and STOP
STOP       = OpCode("STOP",       0x00, 0, 0, 0)
ADD        = OpCode("ADD",        0x01, 2, 1, 3)
MUL        = OpCode("MUL",        0x02, 2, 1, 5)
SUB        = OpCode("SUB",        0x03, 2, 1, 3)
DIV        = OpCode("DIV",        0x04, 2, 1, 5)
SDIV       = OpCode("SDIV",       0x05, 2, 1, 5)
MOD        = OpCode("MOD",        0x06, 2, 1, 5)
SMOD       = OpCode("SMOD",       0x07, 2, 1, 5)
ADDMOD     = OpCode("ADDMOD",     0x08, 3, 1, 8)
MULMOD     = OpCode("MULMOD",     0x09, 3, 1, 8)
EXP        = OpCode("EXP",        0x0a, 2, 1, 10)
SIGNEXTEND = OpCode("SIGNEXTEND", 0x0b, 2, 1, 5)

# Comparison and Bitwise Logic
LT     = OpCode("LT",     0x10, 2, 1, 3)
GT     = OpCode("GT",     0x11, 2, 1, 3)
SLT    = OpCode("SLT",    0x12, 2, 1, 3)
SGT    = OpCode("SGT",    0x13, 2, 1, 3)
EQ     = OpCode("EQ",     0x14, 2, 1, 3)
ISZERO = OpCode("ISZERO", 0x15, 1, 1, 3)
AND    = OpCode("AND",    0x16, 2, 1, 3)
OR     = OpCode("OR",     0x17, 2, 1, 3)
XOR    = OpCode("XOR",    0x18, 2, 1, 3)
NOT    = OpCode("NOT",    0x19, 1, 1, 3)
BYTE   = OpCode("BYTE",   0x1a, 2, 1, 3)
SHL    = OpCode("SHL", 0x1b, 2, 1, 3)
SHR    = OpCode("SHR", 0x1c, 2, 1, 3)
SAR    = OpCode("SAR", 0x1d, 2, 1, 3)

SHA3 = OpCode("SHA3", 0x20, 2, 1, 30)

# Environmental Information
ADDRESS      = OpCode("ADDRESS",      0x30, 0, 1, 2)
BALANCE      = OpCode("BALANCE",      0x31, 1, 1, 400)
ORIGIN       = OpCode("ORIGIN",       0x32, 0, 1, 2)
CALLER       = OpCode("CALLER",       0x33, 0, 1, 2)
CALLVALUE    = OpCode("CALLVALUE",    0x34, 0, 1, 2)
CALLDATALOAD = OpCode("CALLDATALOAD", 0x35, 1, 1, 3)
CALLDATASIZE = OpCode("CALLDATASIZE", 0x36, 0, 1, 2)
CALLDATACOPY = OpCode("CALLDATACOPY", 0x37, 3, 0, 3)
CODESIZE     = OpCode("CODESIZE",     0x38, 0, 1, 2)
CODECOPY     = OpCode("CODECOPY",     0x39, 3, 0, 3) # Gverylow + Gcopy × dµs[2] ÷ 32e
GASPRICE     = OpCode("GASPRICE",     0x3a, 0, 1, 2)
EXTCODESIZE  = OpCode("EXTCODESIZE",  0x3b, 1, 1, 700)
EXTCODECOPY  = OpCode("EXTCODECOPY",  0x3c, 4, 0, 700) # Gextcode + Gcopy × dµs[3] ÷ 32e if w = EXTCODECOPY

# Block Information
BLOCKHASH  = OpCode("BLOCKHASH",  0x40, 1, 1, 20)
COINBASE   = OpCode("COINBASE",   0x41, 0, 1, 2)
TIMESTAMP  = OpCode("TIMESTAMP",  0x42, 0, 1, 2)
NUMBER     = OpCode("NUMBER",     0x43, 0, 1, 2)
DIFFICULTY = OpCode("DIFFICULTY", 0x44, 0, 1, 2)
GASLIMIT   = OpCode("GASLIMIT",   0x45, 0, 1, 2)
BASEFEE    = OpCode("BASEFEE",  0x48, 0, 1, 2)

# Stack, Memory, Storage, Flow
POP      = OpCode("POP",      0x50, 1, 0, 2)
MLOAD    = OpCode("MLOAD",    0x51, 1, 1, 3)
MSTORE   = OpCode("MSTORE",   0x52, 2, 0, 3)
MSTORE8  = OpCode("MSTORE8",  0x53, 2, 0, 3)
SLOAD    = OpCode("SLOAD",    0x54, 1, 1, 200)
SSTORE   = OpCode("SSTORE",   0x55, 2, 0, 5000)
JUMP     = OpCode("JUMP",     0x56, 1, 0, 8)
JUMPI    = OpCode("JUMPI",    0x57, 2, 0, 10)
PC       = OpCode("PC",       0x58, 0, 1, 2)
MSIZE    = OpCode("MSIZE",    0x59, 0, 1, 2)
GAS      = OpCode("GAS",      0x5a, 0, 1, 2)
JUMPDEST = OpCode("JUMPDEST", 0x5b, 0, 0, 1)

PUSH0  = OpCode("PUSH0",  0x5f, 0, 1, 2)
PUSH1  = OpCode("PUSH1",  0x60, 0, 1, 3)
PUSH2  = OpCode("PUSH2",  0x61, 0, 1, 3)
PUSH3  = OpCode("PUSH3",  0x62, 0, 1, 3)
PUSH4  = OpCode("PUSH4",  0x63, 0, 1, 3)
PUSH5  = OpCode("PUSH5",  0x64, 0, 1, 3)
PUSH6  = OpCode("PUSH6",  0x65, 0, 1, 3)
PUSH7  = OpCode("PUSH7",  0x66, 0, 1, 3)
PUSH8  = OpCode("PUSH8",  0x67, 0, 1, 3)
PUSH9  = OpCode("PUSH9",  0x68, 0, 1, 3)
PUSH10 = OpCode("PUSH10", 0x69, 0, 1, 3)
PUSH11 = OpCode("PUSH11", 0x6a, 0, 1, 3)
PUSH12 = OpCode("PUSH12", 0x6b, 0, 1, 3)
PUSH13 = OpCode("PUSH13", 0x6c, 0, 1, 3)
PUSH14 = OpCode("PUSH14", 0x6d, 0, 1, 3)
PUSH15 = OpCode("PUSH15", 0x6e, 0, 1, 3)
PUSH16 = OpCode("PUSH16", 0x6f, 0, 1, 3)
PUSH17 = OpCode("PUSH17", 0x70, 0, 1, 3)
PUSH18 = OpCode("PUSH18", 0x71, 0, 1, 3)
PUSH19 = OpCode("PUSH19", 0x72, 0, 1, 3)
PUSH20 = OpCode("PUSH20", 0x73, 0, 1, 3)
PUSH21 = OpCode("PUSH21", 0x74, 0, 1, 3)
PUSH22 = OpCode("PUSH22", 0x75, 0, 1, 3)
PUSH23 = OpCode("PUSH23", 0x76, 0, 1, 3)
PUSH24 = OpCode("PUSH24", 0x77, 0, 1, 3)
PUSH25 = OpCode("PUSH25", 0x78, 0, 1, 3)
PUSH26 = OpCode("PUSH26", 0x79, 0, 1, 3)
PUSH27 = OpCode("PUSH27", 0x7a, 0, 1, 3)
PUSH28 = OpCode("PUSH28", 0x7b, 0, 1, 3)
PUSH29 = OpCode("PUSH29", 0x7c, 0, 1, 3)
PUSH30 = OpCode("PUSH30", 0x7d, 0, 1, 3)
PUSH31 = OpCode("PUSH31", 0x7e, 0, 1, 3)
PUSH32 = OpCode("PUSH32", 0x7f, 0, 1, 3)

DUP1  = OpCode("DUP1",  0x80, 1, 2, 3)
DUP2  = OpCode("DUP2",  0x81, 2, 3, 3)
DUP3  = OpCode("DUP3",  0x82, 3, 4, 3)
DUP4  = OpCode("DUP4",  0x83, 4, 5, 3)
DUP5  = OpCode("DUP5",  0x84, 5, 6, 3)
DUP6  = OpCode("DUP6",  0x85, 6, 7, 3)
DUP7  = OpCode("DUP7",  0x86, 7, 8, 3)
DUP8  = OpCode("DUP8",  0x87, 8, 9, 3)
DUP9  = OpCode("DUP9",  0x88, 9, 10, 3)
DUP10 = OpCode("DUP10", 0x89, 10, 11, 3)
DUP11 = OpCode("DUP11", 0x8a, 11, 12, 3)
DUP12 = OpCode("DUP12", 0x8b, 12, 13, 3)
DUP13 = OpCode("DUP13", 0x8c, 13, 14, 3)
DUP14 = OpCode("DUP14", 0x8d, 14, 15, 3)
DUP15 = OpCode("DUP15", 0x8e, 15, 16, 3)
DUP16 = OpCode("DUP16", 0x8f, 16, 17, 3)

SWAP1  = OpCode("SWAP1",  0x90, 2, 2, 3)
SWAP2  = OpCode("SWAP2",  0x91, 3, 3, 3)
SWAP3  = OpCode("SWAP3",  0x92, 4, 4, 3)
SWAP4  = OpCode("SWAP4",  0x93, 5, 5, 3)
SWAP5  = OpCode("SWAP5",  0x94, 6, 6, 3)
SWAP6  = OpCode("SWAP6",  0x95, 7, 7, 3)
SWAP7  = OpCode("SWAP7",  0x96, 8, 8, 3)
SWAP8  = OpCode("SWAP8",  0x97, 9, 9, 3)
SWAP9  = OpCode("SWAP9",  0x98, 10, 10, 3)
SWAP10 = OpCode("SWAP10", 0x99, 11, 11, 3)
SWAP11 = OpCode("SWAP11", 0x9a, 12, 12, 3)
SWAP12 = OpCode("SWAP12", 0x9b, 13, 13, 3)
SWAP13 = OpCode("SWAP13", 0x9c, 14, 14, 3)
SWAP14 = OpCode("SWAP14", 0x9d, 15, 15, 3)
SWAP15 = OpCode("SWAP15", 0x9e, 16, 16, 3)
SWAP16 = OpCode("SWAP16", 0x9f, 17, 17, 3)

# Logging
LOG0 = OpCode("LOG0", 0xa0, 2, 0, 375) # Glog + Glogdata × µs[1]
LOG1 = OpCode("LOG1", 0xa1, 3, 0, 750) # Glog + Glogdata × µs[1] + Glogtopic
LOG2 = OpCode("LOG2", 0xa2, 4, 0, 1125) # Glog + Glogdata × µs[1] + 2Glogtopic
LOG3 = OpCode("LOG3", 0xa3, 5, 0, 1500) # Glog + Glogdata × µs[1] + 3Glogtopic
LOG4 = OpCode("LOG4", 0xa4, 6, 0, 1850) # Glog + Glogdata × µs[1] + 4Glogtopic

# System Operations
CREATE       = OpCode("CREATE",       0xf0, 3, 1, 32000)
CALL         = OpCode("CALL",         0xf1, 7, 1, 700)
CALLCODE     = OpCode("CALLCODE",     0xf2, 7, 1, 700)
RETURN       = OpCode("RETURN",       0xf3, 2, 0, 0)
DELEGATECALL = OpCode("DELEGATECALL", 0xf4, 6, 1, 700)
CREATE2      = OpCode("CREATE2",      0xf5, 4, 1, 32000)
INVALID      = OpCode("INVALID",      0xfe, 0, 0, 0)
SELFDESTRUCT = OpCode("SELFDESTRUCT", 0xff, 1, 0, 5000)

# New Byzantinium OpCodes for block.number >= BYZANTIUM_FORK_BLKNUM
REVERT = OpCode("REVERT", 0xfd, 2, 0, 0) #TODO gas 
RETURNDATASIZE = OpCode("RETURNDATASIZE", 0x3d, 0, 1, 2)
RETURNDATACOPY = OpCode("RETURNDATACOPY", 0x3e, 3, 0, 3)
STATICCALL = OpCode("STATICCALL", 0xfa, 6, 1, 40)

# New Instanbul and St. Petersburg Opcodes
EXTCODEHASH = OpCode("EXTCODEHASH", 0x3f, 1, 1, 700)
CHAINID = OpCode("CHAINID", 0x46, 0, 1, 2)
SELFBALANCE = OpCode("SELFBALANCE", 0x47, 0, 1, 5)

# Produce mappings from names and instruction codes to opcode objects
OPCODES = {
    code.name: code
    for code in globals().values()
    if isinstance(code, OpCode)
}
"""Dictionary mapping of opcode string names to EVM OpCode objects"""

# Handle incorrect opcode name from go-ethereum disasm
OPCODES["TXGASPRICE"] = OPCODES["GASPRICE"]

BYTECODES = {code.code: code for code in OPCODES.values()}
"""Dictionary mapping of byte values to EVM OpCode objects"""


def opcode_by_name(name: str) -> OpCode:
    """
    Mapping: Retrieves the named OpCode object (case-insensitive).

    Throws:
      LookupError: if there is no opcode defined with the given name.
    """
    name = name.upper()
    if name not in OPCODES:
        raise LookupError("No opcode named '{}'.".format(name))
    return OPCODES[name]


def opcode_by_value(val: int) -> OpCode:
    """
    Mapping: Retrieves the OpCode object with the given value.

    Throws:
      LookupError: if there is no opcode defined with the given value.
    """
    if val not in BYTECODES:
        raise LookupError("No opcode with value '0x{:02X}'.".format(val))
    return BYTECODES[val]


def missing_opcode(val: int) -> OpCode:
    """
    Produces a new OpCode with the given value, as long as that is
    an unknown code.

    Throws:
      ValueError: if there is an opcode defined with the given value.
    """
    if val in BYTECODES:
        raise ValueError("Opcode {} exists.")
    return OpCode("MISSING", val, 0, 0, 0)
