#!/bin/bash

## Code to setup the Cloud Custodian Mailer.  Only needs to be done once.
##
RESOURCE_BUCKET='<SOME-S3-BUCKET>'

## Navigate to opt directory and download the cloud custodian git repo
cd /opt
git clone https://github.com/capitalone/cloud-custodian

## Download our AGT Mailer.yaml template from S3
aws s3 cp "s3://$RESOURCE_BUCKET/mailer.yaml" "/opt/"

## Start the install of the Cloud Custodian Mailer
virtualenv c7n_mailer
source c7n_mailer/bin/activate
cd /opt/cloud-custodian/tools/c7n_mailer
yes | cp /opt/mailer.yaml /opt/cloud-custodian/tools/c7n_mailer

pip install --upgrade --allow-insecure vcversioner vcversioner
pip install -r requirements.txt
pip install --upgrade --allow-insecure functools32 functools32
python setup.py develop
c7n-mailer -c /opt/cloud-custodian/tools/c7n_mailer/mailer.yaml  --update-lambda
