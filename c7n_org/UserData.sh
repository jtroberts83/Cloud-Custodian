#!/bin/bash

################################################################################
## Written by Jamison Roberts 2017 - Updated July 21 2018
################################################################################

export AWS_DEFAULT_REGION='us-east-1'

####  Set Variables Here ######
RESOURCE_BUCKET='YOUR-S3-BUCKET-NAME' ##  SET YOUR S3 BUCKET NAME HERE WHICH HOSTS YOUR C7N-ORG CONFIG AND POLICIES
CellPhoneNumber = '13193339999'       ## Set your cell phone number to be used with AWS SNS to send you a txt when the server starts it's scan.
ASGName = 'CloudCustodianASGName'     ## The name of your single instance ASG. Apply a schedule to the ASG to spin up server every day then this script will shut it down when done.



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
cd /root/c7n_org_policies/regional/
dos2unix *.yaml
cat *.yaml > /tmp/allregional.yaml
sed -i -e 's/policies://g' /tmp/allregional.yaml
echo 'policies:' | cat - /tmp/allregional.yaml > temp && mv temp /tmp/allregional.yaml -f


## This part will run each policy through dos2unix to fix any odd formatting from windows and
## Then all global policies are combined into 1 large policy doc that allows c7n-org to multithread WAY faster!
cd /root/c7n_org_policies/global/
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


## Does a count of how many accounts you have listed in your c7n-org accounts config.yaml file
NumberOfAccounts="$(grep -c 'name' /root/config-Regional.yaml)"
touch /root/start-$NumberOfAccounts.txt
aws s3 cp /root/start-$NumberOfAccounts.txt s3://$RESOURCE_BUCKET/start-$NumberOfAccounts.txt


## Send txt message notification to cell phone indicating it is starting it's run
aws sns publish --phone-number $CellPhoneNumber --message "Executing Custodian Scan Now"


for policyname in "${policyfiles[@]}"; do
    echo "Running custodian with policy file $policyname"
    POLICY_LOG_PATH=$policyname.txt

    ## If its a regional policy run it against the multipls regions
    if [[ $policyname == *"regional"* ]]; then
       c7n-org run -c /root/config-Regional.yaml -u /tmp/allregional.yaml -s /root/org-log --metrics --region us-east-1 --region eu-west-1 |& tee -a $POLICY_PATH                
       ObjectName="${policyname:1}"
       aws s3 cp $POLICY_PATH s3://$RESOURCE_BUCKET/$ObjectName
    
    else ## If its a global policy run it against us-east-1 only
	c7n-org run -c /root/config-Global.yaml -u /tmp/allglobal.yaml -s /root/org-log --metrics --region us-east-1 |& tee -a $POLICY_PATH
	ObjectName="${policyname:1}"
	aws s3 cp $POLICY_PATH s3://$RESOURCE_BUCKET/$ObjectName
    fi
done


touch /root/end.txt
aws s3 cp /root/end.txt s3://$RESOURCE_BUCKET/end.txt


aws autoscaling update-auto-scaling-group --region us-east-1 --auto-scaling-group-name $ASGName --min-size 0 --max-size 0 --desired-capacity 0
