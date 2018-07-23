###########################################################################################################
##    AWS Support Case Duplicator  - Created By Jamison Roberts 2017
##    Use to open duplicate support cases/limit increase requests into all your specified accounts
##    
##    To use this script you need to first create a csv file containing your account numbers and names (format below in vars section)
##    then host the csv file in a private S3 bucket.
##    Open a support case/limit increase in the account you are running this Lambda function in
##    make sure and use a unique Support Case Subject when creating the case as that is how this script knows which case to duplicate
##    Make sure you fill in the variables below
##
############################################################################################################


import boto3
import json
from botocore.client import Config
import datetime

##  Fill Out These Variables:
RoleToAssumeInEachAccount = 'Cloud_Custodian_Role'
SupportCaseSubject = 'service-limit-increase needed'
      ##  The following is vars to the S3 bucket and file which lists all your account numbers and names (You must create this)
      ## The csv must be in the following format:  ["123456789999:account-alias-name1", "99987654321:account-alias-name2", "55544446666888:account-alias-name3"]
s3bucket = 's3bucketname'
Accounts = 'PathToS3Object/AccountNumbersAndNames.csv'


stsClient = boto3.client('sts')
supportclient = boto3.client('support')
region = 'us-east-1'
thisaccount = ((context.invoked_function_arn).split(':'))[4]



def lambda_handler(event, context):
    s3resource = boto3.resource('s3', config=Config(signature_version='s3v4'), region_name="us-east-1")
  
    response = supportclient.describe_cases(
        maxResults=15,
        language='en'
    )

    LatestCase = []
    AllCaseTimes = []
    AllCases = response['cases']
    for case in AllCases:
        Subject = case['subject']
        if SupportCaseSubject in Subject:
            RecentCommunications = case['recentCommunications']['communications']
            Alltimes = []
            for Comm in RecentCommunications:
                TimeCreated = Comm['timeCreated']
                Alltimes.append(TimeCreated)
            Earliest = min(Alltimes)
            AllCaseTimes.append(Earliest)
    
    print(AllCaseTimes)
    LatestCase = max(AllCaseTimes)
    for case in AllCases:
        Subject = case['subject']
        if SupportCaseSubject in Subject:
            RecentCommunications = case['recentCommunications']['communications']
            Alltimes = []
            for Comm in RecentCommunications:
                TimeCreated = Comm['timeCreated']
                if TimeCreated == LatestCase:
                    print('FOUUND YOUR CASE')
                    print(case)
                    supportbody = Comm['body']
                    print(supportbody)
                    serviceCode = case['serviceCode']
                    categoryCode = case['categoryCode']
                    severityCode = case['severityCode']
                    ccEmailAddresses = case['ccEmailAddresses']

           
    print("Most recent case is %s" % LatestCase )
    s3resource.meta.client.download_file(s3bucket, Accounts, '/tmp/accounts.csv')
    f = open('/tmp/accounts.csv', 'r')
    accounts = f.read()
    accounts = json.loads(accounts)


    for item in accounts:
        print(item)
        account = ""
        accountname = ""
        item = item.split(":")
        account = item[0]
        accountname = item[1]
        if thisaccount not in account:
            RoleArn = 'arn:aws:iam::' + account + ':role/' + RoleToAssumeInEachAccount
            Creds = stsClient.assume_role(
                RoleArn=RoleArn,
                RoleSessionName='OpenSupportCases',
                DurationSeconds=900
            )
            AccessKey = ""
            AccessKey = Creds['Credentials']['AccessKeyId']
            SecretAccessKey = ""
            SecretAccessKey = Creds['Credentials']['SecretAccessKey']
            SessionToken = ""
            SessionToken = Creds['Credentials']['SessionToken']
           
            Externalclient = boto3.client('support', aws_access_key_id=AccessKey, aws_secret_access_key=SecretAccessKey, aws_session_token=SessionToken, region_name=region )
            
    
            try:
                NewSupportCaseId = Externalclient.create_case(
                    subject=SupportCaseSubject,
                    serviceCode=serviceCode,
                    severityCode=severityCode,
                    categoryCode=categoryCode,
                    communicationBody=supportbody,
                    ccEmailAddresses=ccEmailAddresses,
                    language='en',
                    issueType='technical'
                )
                
                print("Your New Case ID:   %s" % NewSupportCaseId['caseId'])
            except:
                print('There was an error opening support case.  Make sure the account has Business Support or above.')
        else:
            print('This is the source account for the case so we will not open another in this account')
    return 'Done Creating Support Cases'

