#!/usr/bin/env python3


import glob
import os
import re
import shutil
import subprocess
import sqlite3

from lark import Lark, Tree, Visitor, Token
from pyvis.network import Network

DB_FILE = "gigahorse.sqlite3"

directive_parser = Lark(r"""
    IDENT : /[A-Za-z_][A-Za-z_0-9]*/
    directive_value : ESCAPED_STRING  | IDENT | INT | "true" | "false"
    directive_qualifier : ".input" | ".output" | ".printsize" | ".limitsize"
    qualified_name : IDENT ( "." IDENT )*
    directive : directive_qualifier qualified_name ( "," qualified_name )* ( "(" ( IDENT "=" directive_value ( "," IDENT "=" directive_value )* )? ")" )?

    %import common.ESCAPED_STRING
    %import common.WS
    %import common.INT

    %ignore WS
    """, start="directive", parser='lalr', debug=True)


class DirectiveVisitor(Visitor):

    def __init__(self):
        self.relations = []
        self.current = ""
        self.IO = ""
        self.filename = ""
        self.delimiter = ""

    def visit(self, tree):
        if isinstance(tree, Tree):
            if tree.data == "directive":
                for child in tree.children:
                    self.visit(child)
            elif tree.data == "qualified_name":
                temp = []
                for child in tree.children:
                    temp.append(child)
                temp = ".".join(temp)
                self.relations.append(temp)
            elif tree.data == "directive_value":
                temp = []
                for child in tree.children:
                    temp.append(child)
                temp = ".".join(temp)
                temp = temp.replace('"', '')
                self.__dict__[self.current] = temp
        elif isinstance(tree, Token):
            self.current = tree.value
        else:
            print("Unknown")

net = Network(height='100%', width='100%', bgcolor='#222222',
              font_color='white', directed=True)

if os.path.exists(DB_FILE):
    os.remove(DB_FILE)

con = sqlite3.connect('gigahorse.sqlite3')
cur = con.cursor()

# Create table
cur.execute(
'''CREATE TABLE io_directives(
    r_from STRING,
    r_to   STRING,
    filename STRING,
    type STRING,
    PRIMARY KEY (r_from, r_to, filename, type));
''')

INSERT_STR = "INSERT OR IGNORE INTO io_directives (r_from, r_to, filename, type) VALUES (?, ?, ?, ?)"

for x in glob.glob('../**/*.dl', recursive=True):

    shutil.copyfile(
        x,
        x.replace(".dl", ".cxx")
    )

    head, tail = os.path.split(x)

    temp_file = f'{x}_E'
    c = subprocess.run([
        "g++", "-g", "-o", temp_file, '-E', x.replace(".dl", ".cxx")
    ], capture_output=True)

    os.remove(x.replace(".dl", ".cxx"))

    file = open(temp_file, 'r')
    lines = file.readlines()

    for index, line in enumerate(lines):
        output = False
        if re.search("\.output", line):
            output = True
        elif re.search("\.input", line):
            output = False
        else:
            continue

        d_visitor = DirectiveVisitor()
        d_visitor.visit(directive_parser.parse(line))
        for relation in d_visitor.relations:
            net.add_node(relation)
            filename = d_visitor.filename if len(d_visitor.filename) != 0 else f'{relation}{".csv" if output else ".facts"}'
            net.add_node(filename)
            if output:
                net.add_edge(relation, filename)
                cur.execute(INSERT_STR, (relation, filename, tail, "output"))
            else:
                net.add_edge(filename, relation)
                cur.execute(INSERT_STR, (filename, relation, tail, "input"))

    file.close()
    os.remove(temp_file)

con.commit()
cur.close()

net.show_buttons(filter_=['physics'])
net.save_graph('gigahorse.html')
