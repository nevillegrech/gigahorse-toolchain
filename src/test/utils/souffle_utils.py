import asyncio
import os
import signal
import subprocess
import time
from os.path import join, dirname, abspath, exists
from os import makedirs
from shutil import rmtree
from subprocess import DEVNULL

import src.exporter as exporter
import src.blockparse as blockparse

DEFAULT_SOUFFLE_BIN = 'souffle'

DEFAULT_DECOMPILER_DL = abspath(join(dirname(abspath(__file__)), '..', '..', '..', 'logic/', 'decompiler.dl'))

TEMP_WORKING_DIR = join(dirname(abspath(__file__)), '..', '.temp')


class Decompilation:
    def __init__(self, bytecode_path: str, temp_dir: str = TEMP_WORKING_DIR):
        assert bytecode_path.endswith('.hex'), 'Bytecode file path must be a .hex file'

        self.bytecode_path: str = bytecode_path
        self.id: str = bytecode_path.split('/')[-1].split('.')[0]

        self.work_dir: str = join(temp_dir, f'{self.id}/')
        self.out_dir: str = join(self.work_dir, 'out/')

    def __prepare_directories(self) -> None:
        if exists(self.work_dir):
            rmtree(self.work_dir)

        makedirs(self.out_dir)

    def __generate_facts(self) -> None:
        os.symlink(self.bytecode_path, join(self.work_dir, 'contract.hex'))

        with open(self.bytecode_path) as file:
            bytecode = ''.join([l.strip() for l in file if len(l.strip()) > 0])

            blocks = blockparse.EVMBytecodeParser(bytecode).parse()
            exporter.InstructionTsvExporter(blocks).export(output_dir=self.work_dir, bytecode_hex=bytecode)

    def __decompile(self) -> None:
        args = [
            DEFAULT_SOUFFLE_BIN,
            '-F', abspath(self.work_dir),
            '-D', abspath(self.out_dir),
            DEFAULT_DECOMPILER_DL
        ]

        subprocess.run(args, stdout=subprocess.DEVNULL)



    def run(self):
        self.__prepare_directories()
        self.__generate_facts()
        self.__decompile()
