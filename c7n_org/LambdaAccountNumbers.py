import boto3
from botocore.client import Config
from datetime import datetime, timedelta
import time
import json

RoleName = '<CUSTODIAN-ROLE-NAME-HERE>'
OrgsParentId = '<YOUR-ORG-PARENT-ID>'
orgs = boto3.client('organizations')
bucket = '<YOUR-S3-BUCKET-NAME>'
AccountNumbers_Key = 'AccountNumbers.csv'
AccountNumbersAndNames_Key='AccountNumbersAndNames.csv'
c7n_org_config_template_Key='c7n_org_config_template.txt'
custodian_config_key_regional = 'C7n-Org-Config-Regional.yaml'
custodian_config_key_global = 'C7n-Org-Config-Global.yaml'


stsClient = boto3.client('sts')
def json_serial(obj):
    """JSON serializer for objects not serializable by default json code"""

    if isinstance(obj, datetime):
        serial = obj.isoformat()
        return serial
    raise TypeError ("Type not serializable")


def lambda_handler(event, context):
    timeofevent = datetime.today() - timedelta(hours=6)
    timeofevent = timeofevent.strftime("%Y-%m-%d-%H-%M-%S")
    #print timeofevent
    s3resource = boto3.resource('s3', config=Config(signature_version='s3v4'), region_name="us-east-1")
    s3resource.meta.client.download_file(bucket, c7n_org_config_template_Key, '/tmp/config.txt')
    f = open('/tmp/config.txt', 'r')
    ConfigTemplateOriginal = f.read()
    
    ConfigFileRegional=[]
    ConfigFileRegional.append("accounts:")
    ConfigFileGlobal= []
    ConfigFileGlobal.append("accounts:")
    
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
            account_name = this_account['Name']
            account_output = this_account['Id']
            #print 'Account      ----------------------------------------------------- '
            print json.dumps(account_output,default=json_serial)
            AccountNumbers.append(account_output)
            AccountNumbersAndNames.append(account_output + ':' + account_name)
            ConfigTemplate = ConfigTemplate.replace("<Account_Number>", account_output)
            ConfigTemplate = ConfigTemplate.replace("<Account_Name>", account_name)
            ConfigTemplate = ConfigTemplate.replace("<Role_Name>", RoleName)
            ConfigFileRegional.append(" ")
            ConfigFileRegional.append(ConfigTemplate)
    #print response
    print AccountNumbersAndNames
    
    for all_federated_accounts in all_federated_accounts_info:
        for this_account in all_federated_accounts['Accounts']:
            ConfigTemplate = ConfigTemplateOriginal
            account_name = this_account['Name']
            account_output = this_account['Id']
            ConfigTemplate = ConfigTemplate.replace("<Account_Number>", account_output)
            ConfigTemplate = ConfigTemplate.replace("<Account_Name>", account_name)
            ConfigTemplate = ConfigTemplate.replace("<Role_Name>", RoleName)
            ConfigFileGlobal.append(" ")
            ConfigFileGlobal.append(ConfigTemplate)

    
  
    
    s3Client = boto3.client('s3', 
        config=Config(signature_version='s3v4'), 
        region_name="us-east-1",
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
    
    response = s3Client.put_object(
        Body=ConfigFileRegional,
        Bucket=bucket,
        Key=custodian_config_key_regional
    )
    
    ConfigFileGlobal = '\n'.join(ConfigFileGlobal)
    
    response = s3Client.put_object(
        Body=ConfigFileGlobal,
        Bucket=bucket,
        Key=custodian_config_key_global
    )
