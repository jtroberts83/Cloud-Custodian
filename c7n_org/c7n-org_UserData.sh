#!/bin/bash

export AWS_DEFAULT_REGION='us-east-1'

#Create a python virtual environment
python3 -m venv cc
# Activate the created python virtual environment
. cc/bin/activate
pip install wheel

# Install a static version of custodian and c7n-org (Update these to your version)
pip install 'c7n==0.9.5'
pip install 'c7n_org==0.6.4'
pip install awscli
pip install certifi
cd ..


# The S3 bucket where run logs and policies are stored
RESOURCE_BUCKET='my-s3-bucket'


# Create local directories for the policies to be downloaded to
mkdir /Release
mkdir /Release/regional
mkdir /Release/global

mkdir /ReleaseNonProd/
mkdir /ReleaseNonProd/regional
mkdir /ReleaseNonProd/global

mkdir /ReleaseCanary/
mkdir /ReleaseCanary/regional
mkdir /ReleaseCanary/global

mkdir /ReleaseProdException/
mkdir /ReleaseProdException/global


# This checks the S3 logs bucket for a run log with todays date in its name. If it finds one, notify and abort the policy deployment
# This is because we don't want policies to run more than once per day as it would interfere with policy workflow timing
DATE=$(date +%Y-%m-%d)
for s3object in $(aws s3 ls s3://my-s3-bucket-policies/Logs/ --region us-east-1 | grep ${DATE} ) ;
do
    if [[ $s3object == Release-Prod-start* ]];
    then
        echo $s3object ;
        aws sns publish --message "Custodian Has Already Run Today!!  Check ASG For Failures!" --phone-number 12223334444
        aws autoscaling update-auto-scaling-group --region us-east-1 --auto-scaling-group-name My-Custodian-ASG --min-size 0 --max-size 0 --desired-capacity 0      
        exit 0
    fi
done

# Copies down all the organized custodian policies from the S3 bucket
aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.0.0/regional-poll/ /Release/regional/
aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.0.0/regional-lambda/ /Release/regional/

aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.1.0/regional-poll/ /Release/regional/
aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.1.0/regional-lambda/ /Release/regional/
aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.1.0/global/ /Release/global/

aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.2.0/regional-poll/ /Release/regional/
aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.2.0/regional-lambda/ /Release/regional/

aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.3.0/regional-poll/ /Release/regional/
aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.3.0/regional-lambda/ /Release/regional/

aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.4.0/regional-poll/ /Release/regional/
aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.4.0/regional-lambda/ /Release/regional/
aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.4.0/global/ /Release/global/

aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.5.0/regional-poll/ /Release/regional/
aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.5.0/regional-lambda/ /Release/regional/

aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.6.0/regional-poll/ /Release/regional/
aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.6.0/regional-lambda/ /Release/regional/

aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.7.0/regional-poll/ /Release/regional/
aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.7.0/regional-lambda/ /Release/regional/

aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.8.0/regional-poll/ /Release/regional/
aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.8.0/regional-lambda/ /Release/regional/

aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.9.0/regional-poll/ /Release/regional/
aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.9.0/regional-lambda/ /Release/regional/
aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.9.0/global/ /Release/global/

aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.10.0/regional-poll/ /Release/regional/
aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.10.0/regional-lambda/ /Release/regional/

aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.11.0/regional-poll/ /Release/regional/
aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.11.0/regional-lambda/ /Release/regional/

aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.12.0/regional-poll/ /ReleaseCanary/regional/
aws s3 sync s3://$RESOURCE_BUCKET/Custodian-Policies/Release/1.12.0/regional-lambda/ /ReleaseCanary/regional/


# Copies down the c7n-org accounts config files
aws s3 cp s3://$RESOURCE_BUCKET/c7n_org/C7n-Org-Config-Regional.yaml /root/config-Regional.yaml

# Copies the local syslog to S3 bucket
aws s3 cp /var/log/syslog s3://my-s3-bucket-policies/Logs/SYSLOG.txt

# Goes into policies directory and combines all the individual policies into 1 policy file.
# Removes all the policies: at the top of each file and once all combined into 1 file, adds it back to the top of the new file
cd /Release/regional/
dos2unix *.yaml
cat *.yaml > /tmp/allregional.yaml
sed -i -e 's/policies://g' /tmp/allregional.yaml
echo 'policies:' | cat - /tmp/allregional.yaml > temp && mv temp /tmp/allregional.yaml -f

cd /Release/global/
dos2unix *.yaml
cat *.yaml > /tmp/allglobal.yaml
sed -i -e 's/policies://g' /tmp/allglobal.yaml
echo 'policies:' | cat - /tmp/allglobal.yaml > temp && mv temp /tmp/allglobal.yaml -f


## NonProd Account Policies:

#cd /ReleaseNonProd/regional/
#dos2unix *.yaml
#cat *.yaml > /tmp/allNonProdregional.yaml
#sed -i -e 's/policies://g' /tmp/allNonProdregional.yaml
#echo 'policies:' | cat - /tmp/allNonProdregional.yaml > temp && mv temp /tmp/allNonProdregional.yaml -f

#cd /ReleaseNonProd/global/
#dos2unix *.yaml
#cat *.yaml > /tmp/allNonProdglobal.yaml
#sed -i -e 's/policies://g' /tmp/allNonProdglobal.yaml
#echo 'policies:' | cat - /tmp/allNonProdglobal.yaml > temp && mv temp /tmp/allNonProdglobal.yaml -f



## Canary Account Policies:

cd /ReleaseCanary/regional/
dos2unix *.yaml
cat *.yaml > /tmp/allCanaryregional.yaml
sed -i -e 's/policies://g' /tmp/allCanaryregional.yaml
echo 'policies:' | cat - /tmp/allCanaryregional.yaml > temp && mv temp /tmp/allCanaryregional.yaml -f


#cd /ReleaseCanary/global/
#dos2unix *.yaml
#cat *.yaml > /tmp/allCanaryglobal.yaml
#sed -i -e 's/policies://g' /tmp/allCanaryglobal.yaml
#echo 'policies:' | cat - /tmp/allCanaryglobal.yaml > temp && mv temp /tmp/allCanaryglobal.yaml -f



Policies=("/tmp/allregional.yaml" "/tmp/allglobal.yaml")

policyfiles=(/tmp/allregional.yaml)

DATE=`date +%Y-%m-%d`

# Copies the instance profile credentials down to local variables
creds_file="/root/.aws/credentials"
instance_profile=`curl --noproxy 169.254.169.254 http://169.254.169.254/latest/meta-data/iam/security-credentials/`

aws_access_key_id=`curl -s --noproxy 169.254.169.254 http://169.254.169.254/latest/meta-data/iam/security-credentials/${instance_profile} | grep AccessKeyId | cut -d':' -f2 | sed 's/[^0-9A-Z]*//g'`
aws_secret_access_key=`curl -s --noproxy 169.254.169.254 http://169.254.169.254/latest/meta-data/iam/security-credentials/${instance_profile} | grep SecretAccessKey | cut -d':' -f2 | sed 's/[^0-9A-Za-z/+=]*//g'`
aws_session_token=`curl -s --noproxy 169.254.169.254 http://169.254.169.254/latest/meta-data/iam/security-credentials/${instance_profile} | grep Token | cut -d':' -f2 | sed 's/[^0-9A-Za-z/+=]*//g'`
expire=`curl -s --noproxy 169.254.169.254 http://169.254.169.254/latest/meta-data/iam/security-credentials/${instance_profile} | grep Expiration | sed 's/[^0-9A-Za-z/+=:-]*//g'`
expiretime="${expire/Expiration:/}"


# Sets the instance profile role credentials to the local aws configure profile
# This is done to avoid credential timeout errors when running on a large EC2 instance
aws configure set aws_access_key_id $aws_access_key_id
aws configure set aws_secret_access_key $aws_secret_access_key
aws configure set aws_session_token $aws_session_token


##################################################################################################
####       FULL Release 1.0.0 - 1.11.0 PROD DEPLOY - All Accounts
##################################################################################################

NumberOfAccounts="$(grep -c 'name' /root/config-Regional.yaml)"
touch /root/start-$NumberOfAccounts.txt
aws s3 cp /root/start-$NumberOfAccounts.txt s3://my-s3-bucket-policies/Logs/Release-Prod-start-$NumberOfAccounts.txt
DayOfWeek=`date +%u`


# Full 1.0.0 - 1.11.0 Prod Release Run
echo "Running custodian with Release policy file $policyname"
POLICY_PATH="allregional.txt"
                              
   C7N_ORG_PARALLEL=96 c7n-org run -c /root/config-Regional.yaml -u /tmp/allregional.yaml -s . |& tee -a $POLICY_PATH
   aws s3 cp /var/log/syslog s3://my-s3-bucket-policies/Logs/SYSLOG.txt


MyLogFile="allregional.yaml"
aws s3 cp $POLICY_PATH s3://my-s3-bucket-policies/Logs/Release/regional/$MyLogFile                 

   C7N_ORG_PARALLEL=96 c7n-org run -c /root/config-Regional.yaml -u /tmp/allglobal.yaml -s . -r us-east-1 |& tee -a $POLICY_PATH
   aws s3 cp /var/log/syslog s3://my-s3-bucket-policies/Logs/SYSLOG.txt

MyLogFile="allglobal.yaml"
aws s3 cp $POLICY_PATH s3://my-s3-bucket-policies/Logs/Release/global/$MyLogFile                     

touch /root/end.txt
aws s3 cp /root/end.txt s3://my-s3-bucket-policies/Logs/Release-Prod-end.txt


# Prod Run Done 
touch /root/endReleaseProd.txt
aws s3 cp /root/endReleaseProd.txt s3://my-s3-bucket-policies/Logs/Release-Prod-end.txt






#########################################
##     GET  TEMP  CREDS
#########################################


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



#########################################
## DEPLOY  NON-PROD  POLICIES 1.11.0
#########################################

#aws s3 cp /root/start-$NumberOfAccounts.txt s3://my-s3-bucket-policies/Logs/Release-NonProd-start-$NumberOfAccounts.txt

#echo "Running custodian with Release NonProd policy file"
#POLICY_PATH="allNonProdregional.txt"
#POLICY_PATH_GLOBAL="allNonProdglobal.txt"
                              
#C7N_ORG_PARALLEL=96 c7n-org run -c /root/config-Regional.yaml -u /tmp/allNonProdregional.yaml -s . -t type:Non-Prod |& tee -a $POLICY_PATH


#C7N_ORG_PARALLEL=96 c7n-org run -c /root/config-Regional.yaml -u /tmp/allNonProdglobal.yaml -s . -t type:Non-Prod -r us-east-1 |& tee -a $POLICY_PATH_GLOBAL


#MyLogFile="allNonProdregional.yaml"
aws s3 cp $POLICY_PATH s3://my-s3-bucket-policies/Logs/Release/regional/$MyLogFile                              


#MyLogFile="allNonProdglobal.yaml"
#aws s3 cp $POLICY_PATH_GLOBAL s3://my-s3-bucket-policies/Logs/Release/global/$MyLogFile                          
                                             

#touch /root/endNonProd.txt
#aws s3 cp /root/endNonProd.txt s3://my-s3-bucket-policies/Logs/Release-NonProd-end.txt



#########################################
## DEPLOY  CANARY  POLICIES
#########################################

aws s3 cp /root/start-$NumberOfAccounts.txt s3://my-s3-bucket-policies/Logs/Release-CANARY-start-$NumberOfAccounts.txt

echo "Running custodian with Release CANARY policy file"
POLICY_PATH="allCanaryregional.txt"
POLICY_PATH_GLOBAL="allCanaryglobal.txt"
                              
C7N_ORG_PARALLEL=96 c7n-org run -c /root/config-Regional.yaml -u /tmp/allCanaryregional.yaml -s . --accounts account-alias-1 --accounts account-alias-2 --accounts account-alias-3  |& tee -a $POLICY_PATH

  C7N_ORG_PARALLEL=96 c7n-org run -c /root/config-Regional.yaml -u /tmp/allCanaryglobal.yaml -r us-east-1 -s . --accounts account-alias-1 --accounts account-alias-2 --accounts account-alias-3  |& tee -a $POLICY_PATH_GLOBAL

  aws s3 cp /var/log/syslog s3://my-s3-bucket-policies/Logs/SYSLOG.txt
touch /root/endCANARY.txt
aws s3 cp /root/endCANARY.txt s3://my-s3-bucket-policies/Logs/Canary-end.txt


MyLogFile="allCanaryregional.yaml"
#MyLogFileGlobal="allCanaryglobal.yaml"
aws s3 cp $POLICY_PATH s3://my-s3-bucket-policies/Logs/Release/regional/$MyLogFile
#aws s3 cp $POLICY_PATH_GLOBAL s3://my-s3-bucket-policies/Logs/Release/global/$MyLogFileGlobal


##################################################################################################
####      ALL DONE - SHUT DOWN ASG
##################################################################################################

aws s3 cp /var/log/syslog s3://my-bucket-custodian-policies/Logs/SYSLOG.txt


sleep 30

aws autoscaling update-auto-scaling-group --region us-east-1 --auto-scaling-group-name My-Custodian-ASG --min-size 0 --max-size 0 --desired-capacity 0

sleep 60

aws autoscaling update-auto-scaling-group --region us-east-1 --auto-scaling-group-name My-Custodian-ASG --min-size 0 --max-size 0 --desired-capacity 0
