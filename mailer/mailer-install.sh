#!/bin/bash

## Code to setup the Cloud Custodian Mailer.  Only needs to be done once.
##
RESOURCE_BUCKET='S3BucketName'

## Sets up proxy for this session
export no_proxy="169.254.169.254"
export http_proxy='http://proxyaddress.com:9090'
export https_proxy="$http_proxy"
export NO_PROXY="$no_proxy"
export HTTP_PROXY="$http_proxy"
export HTTPS_PROXY="$http_proxy"

## Navigate to opt directory and download the cloud custodian git repo
cd /opt
git clone https://github.com/capitalone/cloud-custodian

## Download our AGT Mailer.yaml template from S3
aws s3 cp "s3://$RESOURCE_BUCKET/mailer.yaml" "/opt/"

## Start the install of the Cloud Custodian Mailer
virtualenv c7n_mailer
source c7n_mailer/bin/activate
cd /opt/cloud-custodian/tools/c7n_mailer
cp /opt/mailer.yaml /opt/cloud-custodian/tools/c7n_mailer
pip install --upgrade --allow-insecure vcversioner vcversioner
pip install -r requirements.txt
pip install --upgrade --allow-insecure functools32 functools32
python setup.py develop
c7n-mailer -c mailer.yaml