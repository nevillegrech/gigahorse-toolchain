#!/bin/bash
echo "compressing files"
tar -hzcf contract_data.tar.gz --exclude='*.facts' --exclude='*.csv' --exclude '*.err' .temp
echo "copying archive to remote server"    
scp contract_data.tar.gz contract-library:/srv/contract_data/contract_data.tar.gz &&
echo "backing up old data"
ssh contract-library "cd /srv/contract_data ; mv .temp.old /tmp/ ; mv .temp .temp.old"
echo "extracting archive on remote server"
ssh contract-library "cd /srv/contract_data ; nohup tar -xzf contract_data.tar.gz"
echo "cleaning up"
ssh contract-library "cd /srv/contract_data ; nohup rm -rf /tmp/*"
