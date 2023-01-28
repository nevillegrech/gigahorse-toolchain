import csv
import os
from typing import Iterable, List, Dict, Literal, Tuple

from .exporter import Exporter
from .basicblock import EVMBasicBlock

SourceMap = List[Dict[Literal["s", "l", "f", "j"], str]]


def generate(filename, entries):
    with open(filename, "w") as f:
        writer = csv.writer(f, delimiter="\t", lineterminator="\n")
        writer.writerows(entries)


def extract_source_map(source_map: str) -> SourceMap:
    """Decompresses the source mapping into an array of {s: ..., l: ..., f: ..., j: ...}"""

    if source_map is None:
        return []

    locators: list[dict] = []
    for idx, s in enumerate(source_map.split(";")):
        if not s:
            locators.append(locators[-1])
            continue

        s_split = s.split(":")
        locator = {}
        for field_idx, field in enumerate(["s", "l", "f", "j"]):
            if len(s_split) > field_idx and (f := s_split[field_idx]):
                locator[field] = f
            else:
                locator[field] = locators[idx - 1][field]

        locators.append(locator)

    return locators


class SourceMapExporter(Exporter):
    def __init__(self, source_map: str, bytecode_hex: str):
        super().__init__(extract_source_map(source_map))
        self.bytecode = bytecode_hex if bytecode_hex[:2] != "0x" else bytecode_hex[2:]

    def export(self, output_dir=""):
        source_mapped_jumps: List[Tuple] = []

        pc = 0
        for feat in self.source:
            if (jump_type := feat["j"]) != "-":
                source_mapped_jumps.append((hex(pc), jump_type))

            opcode = int(self.bytecode[pc * 2] + self.bytecode[pc * 2 + 1], 16)
            if 0x60 <= opcode < 0x80:
                # it's a push instruction, increment by extra size of instruction
                pc += opcode - 0x5F
            pc += 1
        generate(os.path.join(output_dir, "SourceMappedJump.csv"), source_mapped_jumps)
