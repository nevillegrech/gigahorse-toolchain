#!/bin/bash
tar -hzcvf contract_data.tar.gz &&
rm -rf .temp &
scp contract_data.tar.gz contract-library:/srv/ &&
ssh contract-library "cd /srv ; tar -xzf contract_data.tar.gz"
