##  Script Created by Jamison Roberts 2017
##  
##  I recommend running this script on a Windows EC2 instance in your main AWS account and region.
##  The instance needs to have a Instance Profile Role attached with perms to STS etc
##  Set up a Task Scheduler task to run the script daily to keep the AmazonAMIs.csv file up-to-date
##
##  The script does the following:
##
##  	- Gets temp credentials from the local instance and then uses those to gain further access through STS assumed Creds
##  	- Downloads a csv from S3 which contains a list of all your account numbers you want to run against. (If you have this file)
##  	- Scans each account and region for Amazon owned AMIs and builds an array of them as it finds them
##  	- That AMI array is then saved out to a csv file in C:\temp and uploaded to the S3 bucket specified
##  	- You will most likely need to customize this script based on your environment.
##
##  This script was designed to create this AMI CSV file for use with the below Cloud Custodian policies but could be used for other cases
##
## - name: ec2-tag-stateless-instance-at-launch
##   resource: ec2
##     description: |
##         This policy is triggered on new ec2 instances. If the instance is missing the LoadType tag AND 
##         is using an amazon AMI then it tags the instance with LoadType: stateless
##     mode:
##       type: cloudtrail
##       events:
##         - RunInstances
##     filters:
##       - tag:LoadType: absent
##       - type: value
##         key: "ImageId"
##         op: in
##         value_from:
##            url: s3://somes3bucket/CloudCustodian/AmazonLinuxAMIs.csv
##            format: csv2dict
##     actions:
##       - type: tag
##         key: LoadType
##         value: stateless
##
## - name: ec2-tag-stateful-instance-at-launch
##   resource: ec2
##     description: |
##      This policy is triggered on new ec2 instances. If the instance is missing the LoadType tag AND 
##      is NOT using an amazon AMI then it tags the instance with LoadType: stateful
##     mode:
##       type: cloudtrail
##       events:
##         - RunInstances
##     filters:
##       - tag:LoadType: absent
##       - type: value
##         key: "ImageId"
##         op: not-in
##         value_from:
##            url: s3://somes3bucket/CloudCustodian/AmazonLinuxAMIs.csv
##            format: csv2dict
##     actions:
##       - type: tag
##         key: LoadType
##         value: stateful
##


Write-Host "##################################################################`n`nPlease wait.......Loading AWS Powershell Tools Module..........`n`n##################################################################" -ForegroundColor Green
Import-Module "C:\Program Files (x86)\AWS Tools\PowerShell\AWSPowerShell\AWSPowerShell.psd1"

## Intial Varialbes used to get temp credentials
$RoleToAssume = '<ROLE_NAME_HERE>'   # Used for assume a role accross accounts.  Role name must be consistent across all accounts and be assumable by this role from this account number
$AWSRegion = 'us-east-1' 
$AWSAccount = '<AWS_ACCOUNT_NUMBER>'  # The AWS Account number you are running this script it
$ProxyAddress = "http://proxy.company.com"      # Options are: 
$S3BucketName = "<S3_BUCKET_NAME_HERE>"     # What S3 bucket name to download a AWS Account numbers CSV file from.   This will tell the script what accounts to run against
$S3KeyPathToAWSAccountsCSV = "<S3_KEY_TO_ACCOUNT_NUMBERS_ARRAY_CSV>"     # The Key path to the CSV file in the above bucket
$S3KeyPathToUploadAWSAMIsCSV = "<S3_KEY_TO_AMAZON_OWNED_AMIS_CSV>"     # The Key path of where to upload the AMI CSV file once created


$TotalAPICalls = 0
$Count = 0
$TotalAccounts = 0
$Mode = $null

Write-Host "Getting Temp Creds From Local Instance Metadata Now......" -ForegroundColor Yellow
$Role = $null
$Role = C:\temp\curl.exe -s --noproxy 169.254.169.254 http://169.254.169.254/latest/meta-data/iam/security-credentials/
$Creds = C:\temp\curl.exe -s --noproxy 169.254.169.254 http://169.254.169.254/latest/meta-data/iam/security-credentials/$Role | Out-String | ConvertFrom-Json
$LocalAccessKey = $null
$LocalSecretAccessKey = $null
$LocalSessionToken = $null
$LocalAccessKey = $Creds.AccessKeyId
$LocalSecretAccessKey = $Creds.SecretAccessKey
$LocalSessionToken = $Creds.Token  

Write-Host "Credentials successfully obtained through Instance! " -ForegroundColor Green

    Try
    {
	    Copy-S3Object -BucketName $S3BucketName -Key $S3KeyPathToAWSAccountsCSV -LocalFile C:\temp\AccountNumbers.csv -ErrorAction Stop -AccessKey $LocalAccessKey -SecretKey $LocalSecretAccessKey -SessionToken $LocalSessionToken
        Write-Host "AccountNumbers.csv was successfully downloaded from S3" -ForegroundColor Green 
        $Accounts = Get-Content C:\temp\AccountNumbers.csv | ConvertFrom-Json
	}
Catch
    {
		Write-Host "There was an error downloading AccountNumbers.csv from S3" -ForegroundColor Red 
        break
    }

$RegionsArray = (Get-AWSRegion).Region
$StartTime = $null
$StartTime = (Get-Date -Format u)
$AMIS = $null
$T = @()

function FindAMIs($AccessKey,$SecretAccessKey,$SessionToken,$AccountID,$AccountName)
{
    foreach($Region in $RegionsArray)
    {

        if($Script:T.Count -gt 15100)
        {
            $Script:T += (Get-EC2Image -Region $Region -AccessKey $AccessKey -SecretKey $SecretAccessKey -SessionToken $SessionToken -Owner self -Filter @{Name="name";Value="*amzn*"}).ImageId | Select -Unique
        }
        else
        {
            $Script:T += (Get-EC2Image -Region $Region -AccessKey $AccessKey -SecretKey $SecretAccessKey -SessionToken $SessionToken -Filter @{Name="name";Value="*amzn*"}).ImageId | Select -Unique
        }
        $ScriptCount = $Script:T.Count
        Write-Host "$ScriptCount Amazon AMIs So Far - Scanning $Region" -ForegroundColor Cyan
    }
}

############################################################################################################################
############################################################################################################################
############################################################################################################################

function GetTempCreds($AccountID, $RoleToAssume)
{
    $ArnOfAccount = "arn:aws:iam::$AWSAccount`:role/$RoleToAssume"
    Try
    {
        $CredsRole = $null
        $CredsRole = Use-STSRole -DurationInSeconds 900 -Region $AWSRegion -RoleArn $ArnOfAccount -RoleSessionName "assumedrole" -AccessKey $LocalAccessKey -SecretKey $LocalSecretAccessKey -SessionToken $LocalSessionToken -ErrorAction Stop
        $USAccessKey = $null
        $USSecretAccessKey = $null
        $USSessionToken = $null
        $USAccessKey = $CredsRole.Credentials.AccessKeyId
        $USSecretAccessKey = $CredsRole.Credentials.SecretAccessKey
        $USSessionToken = $CredsRole.Credentials.SessionToken 
    }
    Catch
    {
        Write-Host "There was an error getting credentials from AWS STS Service for role $RoleToAssume on $AccountID with arn of $ArnOfAccount`:`n $_ "
        break
    }

    $ArnOfAccount = "arn:aws:iam::$AccountID`:role/$RoleToAssume"
    Try
    {
        $CredsRole = $null
        $CredsRole = Use-STSRole -DurationInSeconds 900 -Region $AWSRegion -RoleArn $ArnOfAccount -RoleSessionName "AssumedAdmins" -AccessKey $USAccessKey -SecretKey $USSecretAccessKey -SessionToken $USSessionToken -ErrorAction Stop
        $AccessKey = $null
        $SecretAccessKey = $null
        $SessionToken = $null
        $AccessKey = $CredsRole.Credentials.AccessKeyId
        $SecretAccessKey = $CredsRole.Credentials.SecretAccessKey
        $SessionToken = $CredsRole.Credentials.SessionToken 
    }
    Catch
    {
        Write-Host "There was an error getting credentials from AWS STS Service for role $RoleToAssume on $AccountID with arn of $ArnOfAccount`:`n $_ "
        $CredsRole = "FAIL"
    }

    Write-Host -ForegroundColor Green  "Credentials were successfully obtained via STS for role $RoleToAssume on $AccountID"
    
    return $CredsRole
}

#set-awsproxy -hostname $ProxyAddress -port 9090 -username "$AD_UserName" -password "$AD_UserPassword"  #----Sets the Proxy for AWS

foreach($Account in $Accounts)
{
    $AccountID = $null
    $AccountName = $null
    $AccountID = $Account
    $response = $null    
    $response = GetTempCreds $AccountID $RoleToAssume
       
    ## Temp creds recieved now parse them out
    $AccessKey = $null
    $SessionToken = $null
    $SecretAccessKey = $null
    #Sets creds to variables
    if($response -like "FAIL")
    {
        Write-Host "Skipping Account $AccountID as its failed to obtain STS Temp Creds from it " -ForegroundColor Red
    }
    else
    {
        $AccessKey = $response.Credentials.AccessKeyId
        $SecretAccessKey = $response.Credentials.SecretAccessKey
        $SessionToken = $response.Credentials.SessionToken 
        $AccountName = $null
    }
        
    if($AccessKey)
    {
        ##  Get the account alias name and save to variable
        $AccountName = Get-IAMAccountAlias -AccessKey $AccessKey -SecretKey $SecretAccessKey -SessionToken $SessionToken
        $Script:TotalAPICalls ++
        $ValidFederatedAccounts += "$AccountID`t$AccountName"
        $Count ++
        Write-Host " $Count - Successfully Obtained Temp STS Creds from AWS Account   $AccountID - $AccountName --- Searching For Amazon AMIs"
        $TotalAccounts ++

        $Found = FindAMIs $AccessKey $SecretAccessKey $SessionToken $AccountID $AccountName

        if(!($Found))
        {
            Write-Host "     No Custom Amazon AMIs Found in this account" -ForegroundColor Yellow
        }
        else
        {
            Write-Host "     Found Amazon AMIs in this account" -ForegroundColor Green
        }
    }
}

$T = $T | Select -Unique

foreach($C in $T)
{
    $AMIS += "`"$C`","
}

$response = $null
$response = GetTempCreds "$AWSAccount" "$RoleToAssume" #Get creds to upload the newly created AmazonAMIs csv to S3
       
## Temp creds recieved now parse them out
$AccessKey = $null
$SessionToken = $null
$SecretAccessKey = $null
#Sets creds to variables
if($response -like "FAIL")
{
    Write-Host "Skipping Account $AccountID as its failed authorization" -ForegroundColor Red
}
else
{
    $AccessKey = $response.Credentials.AccessKeyId
    $SecretAccessKey = $response.Credentials.SecretAccessKey
    $SessionToken = $response.Credentials.SessionToken                    
}

$AMIS = $AMIS.TrimEnd(",")
Write-Output $AMIS | Out-File C:\temp\AmazonLinuxAMIs.csv -Encoding utf8

Write-S3Object -BucketName $S3BucketName -File C:\temp\AmazonLinuxAMIs.csv -StandardStorage -Key $S3KeyPathToUploadAWSAMIsCSV -AccessKey $AccessKey -SecretKey $SecretAccessKey -SessionToken $SessionToken
