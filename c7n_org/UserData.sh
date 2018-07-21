#!/bin/bash

export AWS_DEFAULT_REGION='us-east-1'

RESOURCE_BUCKET='YOUR-S3-BUCKET-NAME'

## Install the needed components like git, dos2unix, gcc, pip, boto3, virtualenv
yum install git -y
yum install dos2unix -y
yum install gcc -y
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python get-pip.py
python get-pip.py --user
pip install boto3
pip install virtualenv
cd /root

## Downloads latest build of Custodian and installs it along with c7n-org tool for multi-account policy runs
git clone https://github.com/capitalone/cloud-custodian.git
virtualenv custodian
source custodian/bin/activate
pip install cloud-custodian
pip install cloud-custodian/tools/c7n_org
echo "virtualenv custodian" >> /root/.bash_profile
echo "source custodian/bin/activate" >> /root/.bash_profile


mkdir /root/c7n_org_policies
mkdir /root/c7n_org_policies/regional
mkdir /root/c7n_org_policies/global



## Downloads all the policy files from S3
## (I have the policies broken out by poll mode, lambda mode, and global (for services that only reside in us-east-1)
aws s3 sync s3://$RESOURCE_BUCKET/policies/regional-poll/ /root/c7n_org_policies/regional/
aws s3 sync s3://$RESOURCE_BUCKET/policies/regional-lambda/ /root/c7n_org_policies/regional/
aws s3 sync s3://$RESOURCE_BUCKET/policies/global/ /root/c7n_org_policies/global/


## Downloads the c7n-org account config files from S3 (Created 1 for Global Policy run and 1 for Regional policy run)
aws s3 cp s3://$RESOURCE_BUCKET/C7n-Org-Config-Regional.yaml /root/config-Regional.yaml
aws s3 cp s3://$RESOURCE_BUCKET/C7n-Org-Config-Global.yaml /root/config-Global.yaml


## This part will run each policy through dos2unix to fix any odd formatting from windows and
## Then all regional policies are combined into 1 large policy doc that allows c7n-org to multithread WAY faster!
cd /opt/c7n_org_policies/regional/
dos2unix *.yaml
cat *.yaml > /tmp/allregional.yaml
sed -i -e 's/policies://g' /tmp/allregional.yaml
echo 'policies:' | cat - /tmp/allregional.yaml > temp && mv temp /tmp/allregional.yaml -f


## This part will run each policy through dos2unix to fix any odd formatting from windows and
## Then all global policies are combined into 1 large policy doc that allows c7n-org to multithread WAY faster!
cd /opt/c7n_org_policies/global/
dos2unix *.yaml
cat *.yaml > /tmp/allglobal.yaml
sed -i -e 's/policies://g' /tmp/allglobal.yaml
echo 'policies:' | cat - /tmp/allglobal.yaml > temp && mv temp /tmp/allglobal.yaml -f


## Create a list of policies for c7n to process (using the policies we combined from above)
policyfiles=(/tmp/allregional.yaml /tmp/allglobal.yaml)


## This will grab and store the EC2 Instances Temp Creds to local variable so Custodian doesn't have to constantly query the instance metadata site
## This allows custodian to run much faster as it saves on lots of traffic
creds_file="/root/.aws/credentials"
instance_profile=`curl --noproxy 169.254.169.254 http://169.254.169.254/latest/meta-data/iam/security-credentials/`

aws_access_key_id=`curl -s --noproxy 169.254.169.254 http://169.254.169.254/latest/meta-data/iam/security-credentials/${instance_profile} | grep AccessKeyId | cut -d':' -f2 | sed 's/[^0-9A-Z]*//g'`
aws_secret_access_key=`curl -s --noproxy 169.254.169.254 http://169.254.169.254/latest/meta-data/iam/security-credentials/${instance_profile} | grep SecretAccessKey | cut -d':' -f2 | sed 's/[^0-9A-Za-z/+=]*//g'`
aws_session_token=`curl -s --noproxy 169.254.169.254 http://169.254.169.254/latest/meta-data/iam/security-credentials/${instance_profile} | grep Token | cut -d':' -f2 | sed 's/[^0-9A-Za-z/+=]*//g'`
expire=`curl -s --noproxy 169.254.169.254 http://169.254.169.254/latest/meta-data/iam/security-credentials/${instance_profile} | grep Expiration | sed 's/[^0-9A-Za-z/+=:-]*//g'`
expiretime="${expire/Expiration:/}"

aws configure set aws_access_key_id $aws_access_key_id
aws configure set aws_secret_access_key $aws_secret_access_key
aws configure set aws_session_token $aws_session_token



NumberOfAccounts="$(grep -c 'name' /root/config-Regional.yaml)"
touch /root/start-$NumberOfAccounts.txt
aws s3 cp /root/start-$NumberOfAccounts.txt s3://$RESOURCE_BUCKET/start-$NumberOfAccounts.txt



aws sns publish --phone-number "1YOUR-Cell-Phone#" --message "New Custodian Server Ready"

