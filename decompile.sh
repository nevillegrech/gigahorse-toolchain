#!/bin/bash

# This script assumes that it's being run from the root of the gigahorse-toolchain
# directory.

if [[ $# -eq 0 || "$1" == "--help" ]]; then
    echo "Usage: ./decompile.sh [OPTION]+"
    echo "Decompile input smart contract."
    echo ""
    echo "  -i               smart contract bytecode to be decompiled"
    echo "  -c               run in compiled mode (default is interpreted)"
    echo "  -f               path where the fact generation directory will be created"
    echo "  -o               path where the decompilation output will be created"
    echo "  --id             identifier for the current run"
    echo "  --profile        enable profiling"
    echo "  --visualize      run visualize script at the end"
    echo "  --cache          use cached facts/executable if they exist"
    echo "  --force-facts    force fact generation"
    echo "  --force-compile  force generation"
    exit 0
fi

COMPILE=0
PROFILE=0
VISUALIZE=0
FORCEFACTS=0
FORCECOMPILE=0
CACHE=0
CONTRACT=""
FACTDIR=""
OUTDIR=""
ID=""

options=$(getopt -o ci:f:o: -l id:,profile,visualize,cache,force-facts,force-compile -- "$@")

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
        --visualize)
            VISUALIZE=1
            ;;
        --cache)
            CACHE=1
            ;;
        --force-compile)
            FORCECOMPILE=1
            ;;
        --force-facts)
            FORCEFACTS=1
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

if [ "$CONTRACT" == "" ]; then
    echo "No contract specified for decompilation."
    exit 1
fi

if [ "$FACTDIR" == "" ]; then
    echo "No input fact directory specified."
    exit 1
fi

if [ "$OUTDIR" == "" ]; then
    echo "No output directory specified."
    exit 1
fi

# Default ID is the first 15 characters of the file
if [ "$ID" == "" ]; then
    ID=$(basename "$CONTRACT" | sed 's/\.[^.]*$//' | cut -c1-12)
fi

echo "ID: $ID"

INFACTDIR=$FACTDIR/"${ID}_facts"
OUTFACTDIR=$OUTDIR/"${ID}_out/database"

echo "Generating input facts for the decompiler into $INFACTDIR"

pushd . > /dev/null

cd logic
LOGIC_HOME=$PWD

# Generate facts when they don't exist or we want to override them
if [ ! -d $INFACTDIR ] || [ $FORCEFACTS -eq 1 ] || [ $CACHE -eq 0 ]; then
    # Make sure that the directory is clear
    mkdir -p $INFACTDIR
    rm -rf $INFACTDIR/*

    ../bin/generatefacts $CONTRACT $FACTDIR/"${ID}_facts"
fi

if [ $PROFILE -eq 0 ]; then
    PROFILEOPT=""
else
    PROFILEOPT="-p $OUTDIR/${ID}_out/profile.txt"
fi

# Clear output directory
mkdir -p $OUTFACTDIR
rm -rf $OUTFACTDIR/../*
mkdir -p $OUTFACTDIR

if [ $COMPILE -eq 0 ]; then
    echo "Decompiling..."

    souffle -F $INFACTDIR -D $OUTFACTDIR decompiler.dl $PROFILEOPT

    if [ $? -ne 0 ]; then
        exit 1
    fi
else
    echo "Compiling souffle executable..."

    MD5=$(cpp -P decompiler.dl | md5sum | cut -d ' ' -f 1)
    MD5=$(echo $MD5 $PROFILEOPT | md5sum | cut -d ' ' -f 1)

    # Check if the executable exists in the cache
    if [ ! -f ../cache/"${MD5}_compiled" ] || [ $FORCECOMPILE -eq 1 ] || [ $CACHE -eq 0 ]; then
        souffle -F $INFACTDIR -D $OUTFACTDIR decompiler.dl $PROFILEOPT -o ../cache/"${MD5}_compiled"
    fi

    if [ $? -ne 0 ]; then
        exit 1
    fi

    echo "Copying $(realpath ../cache/"${MD5}_compiled") to $(realpath $OUTFACTDIR/../"${ID}_compiled")"
    cp ../cache/"${MD5}_compiled" $OUTFACTDIR/../"${ID}_compiled"

    echo "$MD5"

    $OUTFACTDIR/../"${ID}_compiled"

    if [ $? -ne 0 ]; then
        exit 1
    fi
fi

cd $OUTFACTDIR

if [ $VISUALIZE -eq 1 ]; then
    python3 ${LOGIC_HOME}/visualizeout.py > blocks.out
fi

popd > /dev/null

ln -sfn $OUTFACTDIR/.. decompilation-results
