#!/usr/bin/env python3

import pydot
from collections import defaultdict

BLOCK_SIZE_LIMIT = 10
def parseCsv(name):
    f = open(name+'.csv')
    return [line.strip('\n \t\r').split('\t') for line in f]

special_block_colors = (
    ('Function_Out',0,"yellow"),
    ('Function_Return_Out',1,"orange"),
#    PublicFunctionEntryOut="yellow",
#    ReturnTargetOriginatesIn="purple",
    #FunctionCallOut="grey",
)


function_calls = defaultdict(set)
for k,v in parseCsv('FunctionCall_Out'):
    function_calls[k].add(v)


function_call_return = {a[0] : (a[1], a[2]) for a in parseCsv('FunctionCallReturn_Out')}

block_colors = defaultdict(lambda : "green")

block_property = {}

for k, index, v in special_block_colors:
    special_blocks = [s[index] for s in parseCsv(k)]
    block_property[k] = special_blocks
    for s in special_blocks:
        block_colors[s] = v
    
edges = parseCsv('InsBlockEdge')
stmts = parseCsv('Stmt_BasicBlockHead')

stmtDict = defaultdict(list)

stmt_value = defaultdict(str, dict(parseCsv('PushValue')))

opcodes = dict(parseCsv('Statement_Opcode'))

for stmt, block in stmts:
    stmtDict[block].append(stmt)

def renderBlock(stmts):
    sorted_stmts = sorted(stmts, key = lambda a : int(a, 16))
    sorted_stmts = [s+': '+opcodes[s]+' '+stmt_value[s] for s in sorted_stmts]
    if len(sorted_stmts) > BLOCK_SIZE_LIMIT:
        half_limit = int(BLOCK_SIZE_LIMIT/2)
        sorted_stmts = sorted_stmts[:half_limit] + ['...'] + sorted_stmts[-half_limit:]
    return '\\l'.join(sorted_stmts) + '\\l'
graph = pydot.Dot(graph_type='graph')

nodeDict = { k : pydot.Node(k, label=renderBlock(body), shape="rect", style="filled", fillcolor=block_colors[k]) for k, body in stmtDict.items() }

for _, v in nodeDict.items():
    graph.add_node(v)

for fro, to in edges:
    if fro in function_calls and to in function_calls[fro]:
        # call edge
        graph.add_edge(pydot.Edge(nodeDict[fro], "(%s) call %s"%(fro,to), dir = 'forward', arrowHead = 'normal'))
        if fro not in function_call_return:
            continue
        ret = function_call_return[fro][1]
        # return edge
        graph.add_edge(pydot.Edge("(%s) call %s"%(fro,to), nodeDict[ret], dir = 'forward', arrowHead = 'normal'))
        continue
    if fro in block_property["Function_Return_Out"]:
        continue
    graph.add_edge(pydot.Edge(nodeDict[fro], nodeDict[to], dir = 'forward', arrowHead = 'normal'))

graph.write_png('graph.png')

