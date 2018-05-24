#!/usr/bin/env python3

import pydot
from collections import defaultdict

BLOCK_SIZE_LIMIT = 10
def parseCsv(name):
    f = open(name+'.csv')
    return [line.strip('\n \t\r').split('\t') for line in f]

special_block_colors = dict(
    #FunctionEntryOut="white",
    FunctionReturnOut="orange",
    PublicFunctionEntryOut="yellow",
    #FunctionCallOut="grey",
)

function_calls = dict(parseCsv('FunctionCallOut'))

block_colors = defaultdict(lambda : "green")

block_property = {}

for k, v in special_block_colors.items():
    special_blocks = [s[0] for s in parseCsv(k)]
    block_property[k] = special_blocks
    for s in special_blocks:
        block_colors[s] = v
    
edges = parseCsv('InsBlockEdge')
stmts = parseCsv('Stmt_BasicBlockHead')

stmtDict = defaultdict(list)

opcodes = dict(parseCsv('Statement_Opcode'))

for stmt, block in stmts:
    stmtDict[block].append(stmt)

def renderBlock(stmts):
    sorted_stmts = sorted(stmts, key = lambda a : int(a, 16))
    sorted_stmts = [s+': '+opcodes[s] for s in sorted_stmts]
    if len(sorted_stmts) > BLOCK_SIZE_LIMIT:
        half_limit = int(BLOCK_SIZE_LIMIT/2)
        sorted_stmts = sorted_stmts[:half_limit] + ['...'] + sorted_stmts[-half_limit:]
    return '\n'.join(sorted_stmts)
graph = pydot.Dot(graph_type='graph')

nodeDict = { k : pydot.Node(k, label=renderBlock(body), shape="rect", style="filled", fillcolor=block_colors[k]) for k, body in stmtDict.items() }

for _, v in nodeDict.items():
    graph.add_node(v)

print(function_calls)    
for fro, to in edges:
    #print(fro, ' ', to)
    if fro in function_calls and to == function_calls[fro]:
        print('call ', fro, ' ', to)
        graph.add_edge(pydot.Edge(nodeDict[fro], "(%s) call/cc %s"%(fro,function_calls[fro]), dir = 'forward', arrowHead = 'normal'))
        continue
    else:
        print(to)
    graph.add_edge(pydot.Edge(nodeDict[fro], nodeDict[to], dir = 'forward', arrowHead = 'normal'))

graph.write_png('graph.png')

