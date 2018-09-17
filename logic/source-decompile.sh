#!/bin/bash
set -x
../bin/generatefacts $1 facts-tmp
\rm -rf tac-facts-tmp
mkdir tac-facts-tmp
pushd .
cd tac-facts-tmp
souffle -F ../facts-tmp ../decompiler.dl
souffle ../../../gigahorse-clients/source_decompiler.dl
python3 ../get_source.py
popd
