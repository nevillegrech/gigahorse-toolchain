#!/bin/bash
set -x
\rm -rf facts-tmp
../generatefacts $1 facts-tmp
\rm -rf tac-facts-tmp
mkdir tac-facts-tmp
pushd .
cd tac-facts-tmp
souffle -F ../facts-tmp ../decompiler.dl
souffle ../../../gigahorse-clients/source_decompiler.dl
python3.8 ../../../gigahorse-clients/get_source.py -v -d
popd
