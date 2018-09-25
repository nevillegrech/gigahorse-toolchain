#!/bin/bash
echo "compressing files"
tar -hzcf contract_data.tar.gz .temp --exclude='*.facts' &&
#rm -rf .temp &
echo "copying archive to remote server"    
scp contract_data.tar.gz contract-library:/srv/contract_data.tar.gz &&
echo "extracting archive on remote server"
ssh contract-library "cd /srv ; tar -xzf contract_data.tar.gz"
