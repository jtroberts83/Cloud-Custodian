#!/bin/bash

## Setup logging
exec 3>&1 4>&2 >/var/log/user_data.log 2>&1 # Save logs
set -x # Echo each command before executing (for logs)


CUSTODIAN_BASE='/opt/custodian'
SCRIPTS_BASE='/opt/custodian/lib/python2.7/site-packages/c7n/'
WORKER_BASE="$CUSTODIAN_BASE/sqs"
RESOURCE_BUCKET='<S3-BUCKET-NAME-HERE>'
QUEUE_URL='https://sqs.us-east-1.amazonaws.com/<ACCOUNTNUMBER-HERE>/cloud-custodian'
LOG_BUCKET='agt-cloud-custodian'
# LEFT FOR MANUAL TESTING
#QUEUE_URL='https://sqs.us-east-1.amazonaws.com/<ACCOUNTNUMBER-HERE>/cloud-custodian'
#LOG_BUCKET='cloud-custodian-logs'
AWS_DEFAULT_REGION='us-east-1'

## Upgrade all the things!
 yum update -y
 
## Install/Upgrade System-Wide Python Modules
for egg in pip virtualenv awscli boto3; do
  pip install --upgrade --allow-insecure "$egg" "$egg"
done

## Install Cloud Custodian
virtualenv --python=python2 "$CUSTODIAN_BASE"
source "$CUSTODIAN_BASE/bin/activate"

for egg in vcversioner functools32 c7n; do
  pip install --upgrade --allow-insecure "$egg" "$egg"
done


## Install Custodian Worker  
mkdir "$WORKER_BASE" ; cd "$WORKER_BASE"
aws s3 cp "s3://$RESOURCE_BUCKET/custodianSQS.zip" "$WORKER_BASE/"
aws s3 cp "s3://$RESOURCE_BUCKET/policies/global/globalpolicies.yaml" "$WORKER_BASE/"
aws s3 cp "s3://$RESOURCE_BUCKET/policies/regional/regionalpolicies.yaml" "$WORKER_BASE/"
unzip "$WORKER_BASE/custodianSQS.zip"


## Configure and start the Worker Service
cat << EOF > /usr/lib/systemd/system/c7n.service
[Unit]
Description=Cloud Custodian Worker
After=network.target

[Service]
Environment=AWS_DEFAULT_REGION=$AWS_DEFAULT_REGION
Type=simple
ExecStart=/usr/bin/python $WORKER_BASE/cli.py --queue-url "$QUEUE_URL" --bucket-name "$LOG_BUCKET" --custodian $CUSTODIAN_BASE/bin/custodian --global-configs $WORKER_BASE/globalpolicies.yaml --regional-configs $WORKER_BASE/regionalpolicies.yaml
Restart=always

[Install]
WantedBy=multi-user.target
EOF
 
systemctl enable c7n
systemctl start c7n
