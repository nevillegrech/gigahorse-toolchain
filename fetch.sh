#!/usr/bin/bash

if [[ $# -ne 1 || "$1" == "--help" ]]; then
    echo "Usage: ./fetch.sh <address>"
    echo "Fetch the bytecode a given account"
    exit 0
fi

JSON=$(curl -sfX GET https://contract-library.com/api/contracts/Ethereum/$1)

if [[ $? -ne 0 ]]; then
    echo "Network error or invalid address"
    exit
fi

echo ${JSON} | python -c "import sys,json; print json.load(sys.stdin)['bytecode']" > $1.hex
