#!/bin/bash

## Setup logging
exec 3>&1 4>&2 >/var/log/user_data.log 2>&1 # Save logs
set -x # Echo each command before executing (for logs)


CUSTODIAN_BASE='/opt/cloud_custodian'
WORKER_BASE="$CUSTODIAN_BASE/tools/c7n_org"
RESOURCE_BUCKET='<CLOUD_CUSTODIAN_S3_BUCKET_NAME>'


AWS_DEFAULT_REGION='us-east-1'

## Setup HTTP proxy for use in this script
export no_proxy="169.254.169.254"
export http_proxy='http://proxyaddressifneeded.com:9090'
export https_proxy="$http_proxy"
export NO_PROXY="$no_proxy"
export HTTP_PROXY="$http_proxy"
export HTTPS_PROXY="$http_proxy"


yum install dos2unix -y

aws s3 cp "s3://$RESOURCE_BUCKET/C7n_Org_Account_Runner.sh" "/opt/C7n_Org_Account_Runner.sh"

chmod +x /opt/C7n_Org_Account_Runner.sh
dos2unix /opt/C7n_Org_Account_Runner.sh


## Install/Upgrade System-Wide Python Modules
for egg in pip virtualenv awscli boto3; do
  pip install --upgrade --allow-insecure "$egg" "$egg"
done


## Install Cloud Custodian
virtualenv --python=python2 "$CUSTODIAN_BASE"
source "$CUSTODIAN_BASE/bin/activate"

for egg in vcversioner functools32 c7n c7n_org; do
  pip install --upgrade --allow-insecure "$egg" "$egg"
done



cd /opt
git clone https://github.com/capitalone/cloud-custodian

cd /opt/cloud-custodian/tools/c7n_org
virtualenv c7n_org
python setup.py develop
cd /opt



./C7n_Org_Account_Runner.sh