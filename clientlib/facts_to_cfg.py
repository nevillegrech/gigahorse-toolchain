from typing import Tuple, List, Union, Mapping, Set
from collections import namedtuple, defaultdict
from itertools import chain

Statement = namedtuple('Statement', ['ident', 'op', 'operands', 'defs'])

class Block:
    def __init__(self, ident: str, statements: List[Statement]):
        self.ident = ident
        self.statements = statements
        self.predecessors: List[Block] = []
        self.successors: List[Block] = []

class Function:
    def __init__(self, ident: str, name: str, head_block: Block, is_public: bool, formals: List[str]):
        self.ident = ident
        self.name = name
        self.formals = formals
        self.is_public = is_public
        self.head_block = head_block

def load_csv(path: str, seperator: str='\t') -> List[Union[str, List[str]]]:
    with open(path) as f:
        return [line.split(seperator) for line in f.read().splitlines()]

def load_csv_map(path: str, seperator: str='\t', reverse: bool=False) -> Mapping[str, str]:
    return {y: x for x, y in load_csv(path, seperator)} if reverse else {x: y for x, y in load_csv(path, seperator)}

def load_csv_multimap(path: str, seperator: str='\t', reverse: bool=False) -> Mapping[str, List[str]]:
    ret = defaultdict(list)

    if reverse:
        for y, x in load_csv(path, seperator):
            ret[x].append(y)
    else:
        for x, y in load_csv(path, seperator):
            ret[x].append(y)

    return ret

def construct_cfg() -> Tuple[Mapping[str, Block], Mapping[str, Function]]:
    # Load facts
    tac_function_blocks = load_csv_multimap('InFunction.csv', reverse=True)

    tac_func_id_to_public = load_csv_map('PublicFunction.csv')
    tac_high_level_func_name = load_csv_map('HighLevelFunctionName.csv')

    tac_formal_args: Mapping[str, List[Tuple[str, int]]] = defaultdict(list)
    for func_id, arg, pos in load_csv('FormalArgs.csv'):
        tac_formal_args[func_id].append((arg, int(pos)))
    
    # Inverse mapping
    tac_block_function: Mapping[str, str] = {}
    for func_id, block_ids in tac_function_blocks.items():
        for block in block_ids:
            tac_block_function[block] = func_id


    tac_block_stmts = load_csv_multimap('TAC_Block.csv', reverse=True)
    tac_op = load_csv_map('TAC_Op.csv')

    # Load statement defs/uses
    tac_defs: Mapping[str, List[Tuple[str, int]]] = defaultdict(list)
    for stmt_id, var, pos in load_csv('TAC_Def.csv'):
        tac_defs[stmt_id].append((var, int(pos)))

    tac_uses: Mapping[str, List[Tuple[str, int]]] = defaultdict(list)
    for stmt_id, var, pos in load_csv('TAC_Use.csv'):
        tac_uses[stmt_id].append((var, int(pos)))

    # Load block edges
    tac_block_succ = load_csv_multimap('LocalBlockEdge.csv')
    tac_block_pred: Mapping[str, List[str]] = defaultdict(list)
    for block, succs in tac_block_succ.items():
        for succ in succs:
            tac_block_pred[succ].append(block)

    def stmt_sort_key(stmt_id: str) -> int:
        return int(stmt_id.split('0x')[1].split('_')[0], base=16)

    # Construct blocks
    blocks: Mapping[str, Block] = {}
    for block_id in chain(*tac_function_blocks.values()):
        try:
            statements = [
                Statement(
                    s_id,
                    tac_op[s_id],
                    [var for var, _ in sorted(tac_uses[s_id], key=lambda x: x[1])],
                    [var for var, _ in sorted(tac_defs[s_id], key=lambda x: x[1])]
                ) for s_id in sorted(tac_block_stmts[block_id], key=stmt_sort_key)
            ]
            blocks[block_id] = Block(block_id, statements)
        except:
            __import__('pdb').set_trace()

    # Link blocks together
    for block in blocks.values():
        block.predecessors = [blocks[pred] for pred in tac_block_pred[block.ident]]
        block.successors   = [blocks[succ] for succ in tac_block_succ[block.ident]]

    functions: Mapping[str, Function] = {}
    for block_id, in load_csv('IRFunctionEntry.csv'):
        func_id = tac_block_function[block_id]

        high_level_name = 'fallback()' if tac_func_id_to_public.get(func_id, '_') == '0x0' else tac_high_level_func_name[func_id]
        formals = [var for var, _ in sorted(tac_formal_args[func_id], key=lambda x: x[1])]

        functions[func_id] = Function(func_id, high_level_name, blocks[block_id], func_id in tac_func_id_to_public or func_id == '0x0', formals)

    return blocks, functions
