#!/bin/bash
set -x
../bin/generatefacts $1 facts-tmp
\rm -rf tac-facts-tmp
mkdir tac-facts-tmp
pushd .
cd tac-facts-tmp
souffle -F ../facts-tmp ../decompiler.dl
souffle ../../../gigahorse-clients/source_decompiler.dl
python3 ../../../gigahorse-clients/get_source.py -d -v
popd
