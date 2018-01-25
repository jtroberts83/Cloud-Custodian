import boto3
from botocore.client import Config
from datetime import datetime, timedelta
import time
import json

orgs = boto3.client('organizations')
stsClient = boto3.client('sts')


## --VARIABLES TO SET -- #####################################################
##############################################################################
bucket = 'S3-BUCKET-TO-SAVE-ACCOUNT-AND-CONFIGS-TO'
s3region = 'us-east-1'
AccountNumbers_Key = 'AccountNumbers.csv'
AccountNumbersAndNames_Key='AccountNumbersAndNames.csv'
c7n_org_config_template_Key='c7n_org_config_template.txt'
c7n_guardian_config_template_Key='c7n_guardian_config_template.txt'
custodian_config_key_regional = 'C7n-Org-Config-Regional.yaml'
custodian_config_key_global = 'C7n-Org-Config-Global.yaml'
custodian_guardian_config_key_regional = 'C7n-Guardian-Config.yaml'
OrgsParentId = 'r-111'
CloudCustodianRoleName = 'ROLENAMEFORCUSTODIAN'
STSRoleToAssume = 'RoleWithAccessToWriteFilesToS3Bucket'
S3BucketsAccountNumber = 'XXXXXXXXXXXXXXXXXXXX'





## Function to convert non serialized objects #################################
def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""
    if isinstance(obj, datetime):
        serial = obj.isoformat()
        return serial
    raise TypeError ("Type not serializable")


def lambda_handler(event, context):

    s3resource = boto3.resource('s3', config=Config(signature_version='s3v4'), region_name=s3region)
    s3resource.meta.client.download_file(bucket, c7n_org_config_template_Key, '/tmp/config.txt')
    s3resource.meta.client.download_file(bucket, c7n_guardian_config_template_Key, '/tmp/guardianconfig.txt')
    g = open('/tmp/guardianconfig.txt', 'r')
    GuardianConfigTemplateOriginal = g.read()
    GuardianConfigFile=[]
    GuardianConfigFile.append("accounts:")
    
    f = open('/tmp/config.txt', 'r')
    ConfigTemplateOriginal = f.read()
    ConfigFileRegional=[]
    ConfigFileRegional.append("accounts:")
    ConfigFileGlobal= ""
    
	
	## Paginate through all the Org accounts with the parent ID from variable OrgsParentId #########
    next_token = ' '
    paginator = orgs.get_paginator('list_accounts_for_parent')
    all_federated_accounts_info = paginator.paginate(
    ParentId=OrgsParentId
    )
    AccountNumbers = []
    AccountNumbersAndNames = []
    #print all_federated_accounts
    for all_federated_accounts in all_federated_accounts_info:
        for this_account in all_federated_accounts['Accounts']:
            ConfigTemplate = ConfigTemplateOriginal
            GuardianConfigTemplate = GuardianConfigTemplateOriginal
            account_name = this_account['Name']
            account_output = this_account['Id']
            #print 'Account      ----------------------------------------------------- '
            print json.dumps(account_output,default=json_serial)

            AccountNumbers.append(account_output)
            AccountNumbersAndNames.append(account_output + ':' + account_name)
            ConfigTemplate = ConfigTemplate.replace("<Account_Number>", account_output)
            ConfigTemplate = ConfigTemplate.replace("<Account_Name>", account_name)
            ConfigTemplate = ConfigTemplate.replace("<Role_Name>", CloudCustodianRoleName)
            ConfigFileRegional.append(" ")
            ConfigFileRegional.append(ConfigTemplate)
            
            GuardianConfigTemplate = GuardianConfigTemplate.replace("<Account_Number>", account_output)
            GuardianConfigTemplate = GuardianConfigTemplate.replace("<Account_Name>", account_name)
            GuardianConfigTemplate = GuardianConfigTemplate.replace("<Role_Name>", CloudCustodianRoleName)
            GuardianConfigFile.append(" ")
            GuardianConfigFile.append(GuardianConfigTemplate)
    #print response
    print AccountNumbersAndNames
    

    ConfigFileGlobal = ConfigFileRegional
    FullRoleArn = 'arn:aws:iam::' + S3BucketsAccountNumber + ':role/' + STSRoleToAssume
	
    response = stsClient.assume_role(
        RoleArn=FullRoleArn,
        RoleSessionName='AssumedSTSRoleSession',
        DurationSeconds=900,
    )
    
    AccessKey = response['Credentials']['AccessKeyId']
    SecretAccessKey = response['Credentials']['SecretAccessKey']
    SessionToken = response['Credentials']['SessionToken']
    

    
    s3Client = boto3.client('s3', 
        config=Config(signature_version='s3v4'), 
        region_name="us-east-1",
        aws_access_key_id=AccessKey,
        aws_secret_access_key=SecretAccessKey,
        aws_session_token=SessionToken,
    )

    response = s3Client.put_object(
        Body=json.dumps(AccountNumbers),
        Bucket=bucket,
        Key=AccountNumbers_Key
    )
    
    response = s3Client.put_object(
        Body=json.dumps(AccountNumbersAndNames),
        Bucket=bucket,
        Key=AccountNumbersAndNames_Key
    )

    #print ConfigFileRegional-Regional
    ConfigFileRegional = '\n'.join(ConfigFileRegional)
    GuardianConfigFile = '\n'.join(GuardianConfigFile)
    
    
    response = s3Client.put_object(
        Body=ConfigFileRegional,
        Bucket=bucket,
        Key=custodian_config_key_regional
    )
    
    response = s3Client.put_object(
        Body=GuardianConfigFile,
        Bucket=bucket,
        Key=custodian_guardian_config_key_regional
    )
    ConfigFileGlobal = '\n'.join(ConfigFileGlobal)

	
    response = s3Client.put_object(
        Body=ConfigFileGlobal,
        Bucket=bucket,
        Key=custodian_config_key_global
    )
