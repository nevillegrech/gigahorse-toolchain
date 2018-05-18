#!/usr/bin/env python

import os, sys

def find(contract):
    for dir in os.listdir():
        try:
            with open(os.path.join(dir,'contract_filename.txt')) as f:
                if contract in f.readline():
                    print(dir)
        except FileNotFoundError:
            pass



find(sys.argv[1])

