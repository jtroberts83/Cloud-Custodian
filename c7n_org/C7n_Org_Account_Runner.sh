#!/bin/bash

## Lists the policies to download from S3 and execute
policyfiles="regional/agt-account-policies.yaml regional/agt-ami-policies.yaml regional/agt-asg-policies.yaml regional/agt-ebs-policies.yaml regional/agt-ebs-snapshot-policies.yaml regional/agt-ec2-policies.yaml regional/agt-elb-policies.yaml regional/agt-rds-policies.yaml regional/agt-rds-snapshot-policies.yaml regional/agt-s3-policies.yaml regional/agt-sg-policies.yaml global/agt-global-account-policies.yaml global/agt-global-iam-user-policies.yaml global/agt-global-s3-policies.yaml global/agt-global-vpc-policies.yaml"


ASGName = '<NAME_OF_ASG_RUNNING_C7N>'
RESOURCE_BUCKET='<CLOUD_CUSTODIAN_S3_BUCKET_NAME>'

## Sets up proxy for this session
export no_proxy="169.254.169.254"
export http_proxy='http://proxyifneeded.com:9090'
export https_proxy="$http_proxy"
export NO_PROXY="$no_proxy"
export HTTP_PROXY="$http_proxy"
export HTTPS_PROXY="$http_proxy"


## Creates the directories if they are not there
## rm -fr /opt/c7n_org_logs
mkdir /opt/c7n_org_policies
mkdir /opt/c7n_org_policies/regional
mkdir /opt/c7n_org_policies/global
mkdir /opt/c7n_org_logs
mkdir /opt/c7n_org_logs/regional
mkdir /opt/c7n_org_logs/global
DATE=`date +%Y-%m-%d`

## Downloads all the policy files from the array above from S3
for policyname in $policyfiles; do
    echo "Downloading custodian policy file $policyname"
        aws s3 cp s3://$RESOURCE_BUCKET/policies/$policyname /opt/c7n_org_policies/$policyname
done

aws s3 cp s3://$RESOURCE_BUCKET/C7n-Org-Config-Regional.yaml /opt/cloud-custodian/tools/c7n_org/c7n_org/config-Regional.yaml
aws s3 cp s3://$RESOURCE_BUCKET/C7n-Org-Config-Global.yaml /opt/cloud-custodian/tools/c7n_org/c7n_org/config-Global.yaml
cd /opt/cloud-custodian/tools/c7n_org/c7n_org/
pip install vcversioner
pip install functools32
pip install c7n_org

sed -i -e 's/max_workers=32/max_workers=64/g' /opt/cloud-custodian/tools/c7n_org/c7n_org/cli.py
## Sets the c7n_org environment and runs each policy file
source /opt/cloud-custodian/tools/c7n_org/c7n_org/bin/activate

NumberOfAccounts="$(grep -c 'name' /opt/cloud-custodian/tools/c7n_org/c7n_org/config-Regional.yaml)"
touch /opt/start-$NumberOfAccounts.txt
aws s3 cp /opt/start-$NumberOfAccounts.txt s3://$RESOURCE_BUCKET/Logs/start-$NumberOfAccounts.txt
DayOfWeek='date +%u'

for policyname in $policyfiles; do
    echo "Running custodian with policy file $policyname"
        POLICY_PATH="/opt/c7n_org_logs/$policyname-$DATE.txt"
                ## If its a regional policy run it against the multipls regions
        if [[ $policyname == *"regional"* ]]; then
                ## Run c7n_org with the current policy from the array against all accounts
                if [[ ($policyname == *"account"*)]]; then
                        if [[ ($DayOfWeek == 1)]]; then
                                c7n-org run -c /opt/cloud-custodian/tools/c7n_org/c7n_org/config-Regional.yaml -u /opt/c7n_org_policies/$policyname -s /opt/org-log --cache-period 0  --region eu-central-1 --region eu-west-1 --region eu-west-2 --region us-east-1 --region us-east-2 --region us-west-1 --region us-west-2 |& tee -a $POLICY_PATH
                                aws s3 cp $POLICY_PATH s3://$RESOURCE_BUCKET/Logs/$policyname
                                ## Else its a global policy and should only be run against us-east-1
                        fi
                else

                        c7n-org run -c /opt/cloud-custodian/tools/c7n_org/c7n_org/config-Regional.yaml -u /opt/c7n_org_policies/$policyname -s /opt/org-log --cache-period 0  --region eu-central-1 --region eu-west-1 --region eu-west-2 --region us-east-1 --region us-east-2 --region us-west-1 --region us-west-2 |& tee -a $POLICY_PATH
                       
                        aws s3 cp $POLICY_PATH s3://$RESOURCE_BUCKET/Logs/$policyname
                        ## Else its a global policy and should only be run against us-east-1
                fi
        else
                ## Run c7n_org with the current policy from the array against all accounts
                c7n-org run -c /opt/cloud-custodian/tools/c7n_org/c7n_org/config-Global.yaml -u /opt/c7n_org_policies/$policyname -s /opt/org-log --cache-period 0  --region us-east-1 |& tee -a $POLICY_PATH
                aws s3 cp $POLICY_PATH s3://$RESOURCE_BUCKET/Logs/$policyname
        fi


done

touch /opt/end.txt
aws s3 cp /opt/end.txt s3://$RESOURCE_BUCKET/Logs/end.txt

sleep 2m

aws autoscaling update-auto-scaling-group --auto-scaling-group-name $ASGName --min-size 0 --max-size 0 --desired-capacity 0
