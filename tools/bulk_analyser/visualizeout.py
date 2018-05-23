#!/usr/bin/env python3

import pydot
from collections import defaultdict

def parseCsv(name):
    f = open(name+'.csv')
    return [line.strip('\n \t\r').split('\t') for line in f]

edges = parseCsv('InsBlockEdge')
stmts = parseCsv('Stmt_BasicBlockHead')

stmtDict = defaultdict(list)

opcodes = dict(parseCsv('Statement_Opcode'))

for stmt, block in stmts:
    stmtDict[block].append(stmt)

def renderBlock(stmts):
    sorted_stmts = sorted(stmts, key = lambda a : int(a, 16))
    sorted_stmts = [s+': '+opcodes[s] for s in sorted_stmts]
    if len(sorted_stmts) > 6:
        sorted_stmts = sorted_stmts[:3] + ['...'] + sorted_stmts[-3:]
    return '\n'.join(sorted_stmts)
graph = pydot.Dot(graph_type='graph')

nodeDict = { k : pydot.Node(k, label=renderBlock(body), shape="rect", style="filled", fillcolor="green") for k, body in stmtDict.items() }

for _, v in nodeDict.items():
    graph.add_node(v)

for fro, to in edges:
    print(fro, ' ', to)
    graph.add_edge(pydot.Edge(nodeDict[fro], nodeDict[to], dir = 'forward', arrowHead = 'normal'))

graph.write_png('graph.png')

