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

"""blockparse.py: Parse operation sequences and construct basic blocks"""

import abc
import logging
import typing as t

import src.cfg as cfg
import src.evm_cfg as evm_cfg
import src.opcodes as opcodes
import src.settings as settings

ENDIANNESS = "big"
"""
The endianness to use when parsing hexadecimal or binary files.
"""


class BlockParser(abc.ABC):
    @abc.abstractmethod
    def __init__(self, raw: object):
        """
        Constructs a new BlockParser for parsing the given raw input object.

        Args:
          raw: parser-specific object containing raw input to be parsed.
        """

        self._raw = raw
        """raw: parser-specific object containing raw input to be parsed."""

        self._ops = []
        """
        List of program operations extracted from the raw input object.
        Indices from this list are used as unique identifiers for program
        operations when constructing BasicBlocks.
        """

    @abc.abstractmethod
    def parse(self) -> t.Iterable[cfg.BasicBlock]:
        """
        Parses the raw input object and returns an iterable of BasicBlocks.
        """
        self._ops = []
        return self._ops


class EVMDasmParser(BlockParser):
    def __init__(self, dasm: t.Iterable[str]):
        """
        Parses raw EVM disassembly lines and creates corresponding EVMBasicBlocks.
        This does NOT follow jumps or create graph edges - it just parses the
        disassembly and creates the blocks.

        Args:
          dasm: iterable of raw disasm output lines to be parsed by this instance
        """
        super().__init__(dasm)

    def parse(self):
        """
        Parses the raw input object containing EVM disassembly
        and returns an iterable of EVMBasicBlocks.
        """

        super().parse()

        # Construct a list of EVMOp objects from the raw input disassembly
        # lines, ignoring the first line of input (which is the bytecode's hex
        # representation when using Ethereum's disasm tool). Any line which does
        # not produce enough tokens to be valid disassembly after being split() is
        # also ignored.
        for i, l in enumerate(self._raw):
            if len(l.split()) == 1:
                logging.debug("Line %s: invalid disassembly:\n   %s", i + 1, l.rstrip())
                if settings.strict:
                    raise RuntimeError("Line {}: invalid disassembly {}".format(i + 1, l))
                continue
            elif len(l.split()) < 1:
                if settings.strict:
                    logging.warning("Line %s: empty disassembly.", i + 1)
                    raise RuntimeError("Line {}: empty disassembly.".format(i + 1))
                continue

            try:
                self._ops.append(self.evm_op_from_dasm(l))
            except (ValueError, LookupError, NotImplementedError) as e:
                logging.debug("Line %s: invalid disassembly:\n   %s", i + 1, l.rstrip())
                if settings.strict:
                    raise e

        return evm_cfg.blocks_from_ops(self._ops)

    @staticmethod
    def evm_op_from_dasm(line: str) -> evm_cfg.EVMOp:
        """
        Creates and returns a new EVMOp object from a raw line of disassembly.

        Args:
          line: raw line of output from Ethereum's disasm disassembler.

        Returns:
          evm_cfg.EVMOp: the constructed EVMOp
        """
        toks = line.replace("=>", " ").split()

        # Convert hex PCs to ints
        if toks[0].startswith("0x"):
            toks[0] = int(toks[0], 16)

        if len(toks) > 2:
            val = int(toks[2], 16)
            try:
                return evm_cfg.EVMOp(int(toks[0]), opcodes.opcode_by_name(toks[1]), val)
            except LookupError as e:
                return evm_cfg.EVMOp(int(toks[0]), opcodes.missing_opcode(val), val)
        elif len(toks) > 1:
            return evm_cfg.EVMOp(int(toks[0]), opcodes.opcode_by_name(toks[1]))
        else:
            raise NotImplementedError("Could not parse unknown disassembly format:" +
                                      "\n    {}".format(line))


class EVMBytecodeParser(BlockParser):
    def __init__(self, bytecode: t.Union[str, bytes]):
        """
        Parse EVM bytecode directly into basic blocks.

        Args:
          bytecode: EVM bytecode, either as a hexadecimal string or a bytes
            object. If given as a hex string, it may optionally start with 0x.
        """
        super().__init__(bytecode)

        if type(bytecode) is str:
            bytecode = bytes.fromhex(bytecode.replace("0x", ""))
        else:
            bytecode = bytes(bytecode)

        self._raw = bytecode

        # Track the program counter as we traverse the bytecode
        self.__pc = 0

    def __consume(self, n):
        bytes_ = self._raw[self.__pc: self.__pc + n]
        self.__pc += n
        return bytes_

    def __has_more_bytes(self):
        return self.__pc < len(self._raw)

    def parse(self) -> t.Iterable[evm_cfg.EVMBasicBlock]:
        """
        Parses the raw input object containing EVM bytecode
        and returns an iterable of EVMBasicBlocks.
        """

        super().parse()

        while self.__has_more_bytes():
            pc = self.__pc
            byte = int.from_bytes(self.__consume(1), ENDIANNESS)
            const, const_size = None, 0

            try:
                # try to resolve the byte to an opcode
                op = opcodes.opcode_by_value(byte)

            except LookupError as e:
                # oops, unknown opcode
                if settings.strict:
                    logging.warning("(strict) Invalid opcode at PC = %#02x: %s", pc, str(e))
                    raise e
                # not strict, so just log:
                logging.debug("Invalid opcode at PC = %#02x: %s", pc, str(e))
                op = opcodes.missing_opcode(byte)
                const = byte

            # push codes have an argument
            if op.is_push():
                const_size = op.push_len()

            # for opcodes with an argument, consume the argument
            if const_size > 0:
                const = int.from_bytes(self.__consume(const_size), ENDIANNESS)

            self._ops.append(evm_cfg.EVMOp(pc, op, const))

        # build basic blocks from the sequence of opcodes
        return evm_cfg.blocks_from_ops(self._ops)
