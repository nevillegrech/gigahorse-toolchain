#!/usr/bin/env python3

import pydot
from collections import defaultdict


BLOCK_SIZE_LIMIT = 10
def parseCsv(name):
    f = open(name+'.csv')
    return [line.strip('\n \t\r').split('\t') for line in f]

def load_tac_blocks():
    out = defaultdict(list)
    for s, b in parseCsv('TAC_Block'):
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
function_arguments = load_tac_sorted('FormalArgs')
high_level_function_name = dict(parseCsv('HighLevelFunctionName'))
tac_op = dict(parseCsv('TAC_Op'))
variable_value = dict(parseCsv('TAC_Variable_Value'))


special_block_colors = (
    ('Function',0,"yellow"),
    ('IRFunction_Return',1,"orange"),
#    PublicFunctionEntryOut="yellow",
#    ReturnTargetOriginatesIn="purple",
    #FunctionCallOut="grey",
)


function_calls = defaultdict(set)
for k,v in parseCsv('IRFunctionCall'):
    function_calls[k].add(v)


function_call_return = {a[0] : (a[1], a[2]) for a in parseCsv('IRFunctionCallReturn')}

functions = {a[0]  for a in parseCsv('Function')}
function_entries = {a[0]  for a in parseCsv('IRFunctionEntry')}
in_function = dict(parseCsv('InFunction'))

block_colors = defaultdict(lambda : "green")

block_property = {}

for k, index, v in special_block_colors:
    special_blocks = [s[index] for s in parseCsv(k)]
    block_property[k] = special_blocks
    for s in special_blocks:
        block_colors[s] = v
    
edges = parseCsv('LocalBlockEdge')
def prev_block(block):
    return {k for k,v in edges if v == block}
def next_block(block):
    return {v for k,v in edges if k == block}

def format_var(v):
    if v in variable_value:
        value = '('+variable_value[v]+')'
    else:
        value = ''
    return 'v' + v.replace('0x', '')+value

rendered_statements = {}
def renderBlock(k, stmts):
    sorted_stmts = []
    if k in function_entries:
        function_name = high_level_function_name[in_function[k]]
        sorted_stmts.append("function %s(%s)"%(function_name, ', '.join(map(format_var, function_arguments[k]))))
    sorted_stmts.append("Block %s"%k)                        
    for s in sorted(stmts, key = lambda a: int(a.split('0x')[1].split('_')[0], base=16)):
        op = tac_op[s]
        if s in tac_def:
            ret = ', '.join(format_var(v) for v in tac_def[s]) + ' = '
        else:
            ret = ''
        use = ' '.join(format_var(v) for v in tac_use[s])
        stmt_render = s+': '+ret+op+' '+use
        if len(stmt_render) > 60:
            stmt_render = stmt_render[:29] + '...' + stmt_render[-29:]
        sorted_stmts.append(stmt_render)
    if len(sorted_stmts) > BLOCK_SIZE_LIMIT:
        half_limit = int(BLOCK_SIZE_LIMIT/2)
        truncated_stmts = sorted_stmts[:half_limit] + ['...'] + sorted_stmts[-half_limit:]
    else: truncated_stmts = sorted_stmts
    rendered_statements[k] = sorted_stmts
    return '\\l'.join(truncated_stmts) + '\\l'
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
    if fro in block_property["IRFunction_Return"]:
        continue
    graph.add_edge(pydot.Edge(nodeDict[fro], nodeDict[to], dir = 'forward', arrowHead = 'normal'))

for key in rendered_statements:
    print()
    print('Begin block %s'%key)
    print('prev = %s, next = %s'%(prev_block(key), next_block(key)))
    print('----------------------------------')
    print('\n'.join(rendered_statements[key]))
    print('----------------------------------')
graph.write_png('graph.png')

