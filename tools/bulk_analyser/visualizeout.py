#!/usr/bin/env python3

import pydot
from collections import defaultdict


BLOCK_SIZE_LIMIT = 10
def parseCsv(name):
    f = open(name+'.csv')
    return [line.strip('\n \t\r').split('\t') for line in f]

def load_tac_blocks():
    out = defaultdict(list)
    for b, s in parseCsv('TAC_Block'):
        out[b].append(s)
    def sortkey(a):
        try:
            return int(a, 16)
        except Exception:
            return 0
    return {k:sorted(ss, key = sortkey) for k, ss in out.items()}

def load_tac_sorted(prop):
    out = defaultdict(list)
    for s, v, n in parseCsv(prop):
        n = int(n)
        while n > len(out[s]) - 1:
            out[s].append('')
        if n<0:
            out[s].append(v)
        else:
            out[s][n] = v
    return out

tac_blocks = defaultdict(list,load_tac_blocks())
tac_use = load_tac_sorted('TAC_Use')
tac_def = load_tac_sorted('TAC_Def')
function_arguments = load_tac_sorted('FunctionArgument_Out')
tac_op = dict(parseCsv('TAC_Op'))
variable_value = dict(parseCsv('TAC_Variable_Value'))


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

functions = {a[0]  for a in parseCsv('Function_Out')}

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

def format_var(v):
    if v in variable_value:
        value = '('+variable_value[v]+')'
    else:
        value = ''
    return 'v' + v.replace('0x', '')+value

    
def renderBlock(k, stmts):
    sorted_stmts = []
    if k in functions:
        sorted_stmts.append("function %s(%s)"%(k, ', '.join(map(format_var, function_arguments[k]))))
                            
    for s in stmts:
        op = tac_op[s]
        if s in tac_def:
            ret = ', '.join(format_var(v) for v in tac_def[s]) + ' = '
        else:
            ret = ''
        use = ' '.join(format_var(v) for v in tac_use[s])
        sorted_stmts.append(ret+op+' '+use)
    if len(sorted_stmts) > BLOCK_SIZE_LIMIT:
        half_limit = int(BLOCK_SIZE_LIMIT/2)
        sorted_stmts = sorted_stmts[:half_limit] + ['...'] + sorted_stmts[-half_limit:]
    return '\\l'.join(sorted_stmts) + '\\l'
graph = pydot.Dot(graph_type='graph')

for fro, to in edges:
    # insert default placeholder items
    tac_blocks[fro] ; tac_blocks[to]

nodeDict = { k : pydot.Node(k, label=renderBlock(k, body), shape="rect", style="filled", fillcolor=block_colors[k]) for k, body in tac_blocks.items() }

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

