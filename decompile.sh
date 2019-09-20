#!/bin/bash

# This script assumes that it's being run from the root of the gigahorse-toolchain
# directory.

if [[ $# -eq 0 || "$1" == "--help" ]]; then
    echo "Usage: ./decompile.sh [OPTION]+"
    echo "Decompile input smart contract."
    echo ""
    echo "  -i           smart contract bytecode to be decompiled"
    echo "  -c           run in compiled mode (default is interpreted)"
    echo "  -f           output directory for the input fact generation"
    echo "  -o           output directory for the decompilation facts"
    echo "  --id         identifier for the current run"
    echo "  --profile    enable profiling"
    echo "  --debug      enable debug compiler definition"
    echo "  --visualize  run visualize script at the end"
    echo "  --cache      use cached facts/executable if they exist"
    exit 0
fi

DEBUG=0
COMPILE=0
PROFILE=0
VISUALIZE=0
CONTRACT=""
FACTDIR=""
OUTDIR=""
ID=""

options=$(getopt -o ci:f:o: -l id:,profile,debug,visualize,cache -- "$@")

if [ $? -ne 0 ]; then
    echo "Error: Unknown option provided"
    exit 1
fi

eval set -- "$options"

while true; do
    case $1 in
        --profile)
            PROFILE=1
            ;;
        --debug)
            DEBUG=1
            ;;
        --visualize)
            VISUALIZE=1
            ;;
        --cache)
            CACHE=1
            ;;
        --id)
            shift
            ID=$1
            ;;
        -c)
            COMPILE=1
            ;;
        -i)
            shift
            CONTRACT=$(realpath $1)
            ;;
        -f)
            shift
            FACTDIR=$(realpath $1)
            ;;
        -o)
            shift
            OUTDIR=$(realpath $1)
            ;;
        --)
            shift
            break
            ;;
    esac
    shift
done

if [ "$FACTDIR" == "" ]; then
    echo "No input fact directory specified."
    exit 1
fi

if [ "$OUTDIR" == "" ]; then
    echo "No output directory specified."
    exit 1
fi

if [ "$ID" == "" ]; then
    ID=$(basename "$CONTRACT" | sed 's/\.[^.]*$//' | cut -c1-12)
fi

echo "ID: $ID"
echo "Compile: $COMPILE"
echo "Profile: $PROFILE"
echo "Debug: $DEBUG"
echo "Input directory: $FACTDIR"
echo "Output directory: $OUTDIR"

mkdir -p $FACTDIR
mkdir -p $OUTDIR

echo "Generating input facts for the decompiler into $FACTDIR"

pushd .

cd logic
LOGIC_HOME=$PWD

../bin/generatefacts $CONTRACT $FACTDIR

echo "Decompiling..."
souffle -F $FACTDIR -D $OUTDIR decompiler.dl

cd $OUTDIR

if [ $VISUALIZE -eq 1 ]; then
    python3 ${LOGIC_HOME}/visualizeout.py | tee blocks.out
fi

popd

ln -sfn $OUTDIR decompilation-results
