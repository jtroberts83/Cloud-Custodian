
Write-Host "#######`n`nPlease wait.......Loading AWS Powershell Tools Module..........`n`n#####" -ForegroundColor Green
Import-Module "C:\Program Files (x86)\AWS Tools\PowerShell\AWSPowerShell\AWSPowerShell.psd1"
## Intial Varialbes used to get temp credentials
$RoleToAssume = 'Cloud_Custodian_Role'  #Name of IAM Role with custodian permissions
$AWSRegion = 'us-east-1' 
$AWSAccount = 'XXXXXXXXXXXX'  #Main account that custodian is run in


$TotalAPICalls = 0
$Count = 0
$TotalAccounts = 0
$Mode = $null
$PasswordCount = 0
$LatestAviatrix = @()
$LatestPublic = @()

## YOU WILL NEED TO DOWNLOAD curl.exe to C:\temp directory or change this code to use whatever method you prefer to get the instance creds.

Write-Host "Getting Temp Creds Now......" -ForegroundColor Yellow
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
## Downloads a csv file listing all the account numbers to run this against.  You can change this to point to local file or hardcoded array
    Try
    {
	    Copy-S3Object -BucketName agt-apache-resource-tagger -Key UnresolvedResources/NewAccounts/AccountNumbers.csv -LocalFile C:\temp\AccountNumbers.csv -ErrorAction Stop -AccessKey $LocalAccessKey -SecretKey $LocalSecretAccessKey -SessionToken $LocalSessionToken
        Write-Host "AccountNumbers.csv was successfully downloaded from S3" -ForegroundColor Green 
        $Accounts = Get-Content C:\temp\AccountNumbers.csv | ConvertFrom-Json
	}
Catch
    {
		Write-Host "There was an error downloading AccountNumbers.csv from S3" -ForegroundColor Red 
        break
    }


$RegionsArray = (Get-AWSRegion).Region

 $TotalAPICalls = 0
 $Count = 0
 $TotalAccounts = 0

$Mode = $null







###########################################################################################################################################################
###########################################################################################################################################################
###########################################################################################################################################################
function DeleteLambda($Account)
{
    foreach($Region in $RegionsArray)
    { 
        $AllLambdas = (Get-LMFunctionList -Region $Region -AccessKey $AccessKey -SecretKey $SecretAccessKey -SessionToken $SessionToken).FunctionName
        foreach($Lambda in $AllLambdas)
        {
            if($Lambda -like "custodian-*")
            {
                Try
                {
                    Remove-LMFunction -FunctionName $Lambda -Force -Region $Region -AccessKey $AccessKey -SecretKey $SecretAccessKey -SessionToken $SessionToken -ErrorAction Stop
                    Write-Host "Deleted Lambda Function $Lambda from $Account $Region" -ForegroundColor Green
                }
                Catch
                {
                    Write-Host "Error Deleting Lambda Function from $Account $Region $_" -ForegroundColor Red

                }
            }
        }
    }
}

###########################################################################################################################################################
###########################################################################################################################################################
###########################################################################################################################################################
function DeleteConfigRules($Account)
{
    foreach($Region in $RegionsArray)
    { 
        $AllConfigs = $null
	$AllConfigs = (Get-CFGConfigRule -Region $Region -AccessKey $AccessKey -SecretKey $SecretAccessKey -SessionToken $SessionToken).ConfigRuleName
        foreach($Config in $AllConfigs)
        {
            if($Config -like "custodian-*")
            {
                Try
                {
                    Remove-CFGConfigRule -ConfigRuleName $Config -Force -Region $Region -AccessKey $AccessKey -SecretKey $SecretAccessKey -SessionToken $SessionToken -ErrorAction Stop
                    Write-Host "Deleted Config Rule $Config from $Account $Region" -ForegroundColor Green
                }
                Catch
                {
                    Write-Host "Error Deleting Config Rule $Config  from $Account $Region $_" -ForegroundColor Red

                }
            }
        }
    }
}




###########################################################################################################################################################
###########################################################################################################################################################
###########################################################################################################################################################
function DeleteCWERule($Account)
{
    foreach($Region in $RegionsArray)
    { 
        $Rules = $null
        $Rules = Get-CWERule -Region $Region -AccessKey $AccessKey -SecretKey $SecretAccessKey -SessionToken $SessionToken
        
        foreach($Rule in $Rules)
        {
            if($Rule.Name -like "custodian*")
            {
                $RuleToDelete = $null
                $RuleToDelete = $Rule.Name
            
                $CWERules = $null
                $CWTargs = $null
                $TargetIDs = $null

                ## Gets the Cloudwatch Event Rules Targets and then removes them as you cannot delete a CW Rule with Targets attached.
                Try
                {
                    $TargetIDs = (Get-CWETargetsByRule -Rule $RuleToDelete  -Region $Region -AccessKey $AccessKey -SecretKey $SecretAccessKey -SessionToken $SessionToken).Id
           
                    if($TargetIDs)
                    {
                        foreach($ID in $TargetIDs)
                        {
                            $CWTargs = Remove-CWETarget -Region $Region -Rule $RuleToDelete -Id $ID -AccessKey $AccessKey -SecretKey $SecretAccessKey -SessionToken $SessionToken -Force -ErrorAction Stop
                        
                        }
                    }
                    ##  Once the CWRule targets have all been deleted then delete the CWRule itself
                    $CWERules = Remove-CWERule -Region $Region -Name "$RuleToDelete" -AccessKey $AccessKey -SecretKey $SecretAccessKey -SessionToken $SessionToken -Force -ErrorAction Stop
                    Write-Host "$Account - $Region - Found CWEvent Rule $RuleToDelete, Deleting now"
                }
                Catch
                {
                    Write-Host "Error Deleting CloudWatch Event Rule $RuleToDelete in account $Account"
                }
            }
        }
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
        $CredsRole = Use-STSRole -DurationInSeconds 900 -Region $AWSRegion -RoleArn $ArnOfAccount -RoleSessionName "AssumedAdmins" -AccessKey $LocalAccessKey -SecretKey $LocalSecretAccessKey -SessionToken $LocalSessionToken -ErrorAction Stop
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
        $CredsRole = Use-STSRole -DurationInSeconds 900 -Region $AWSRegion -RoleArn $ArnOfAccount -RoleSessionName "CustodianAssumed" -AccessKey $USAccessKey -SecretKey $USSecretAccessKey -SessionToken $USSessionToken -ErrorAction Stop
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
            Write-Host "Skipping Account $AccountID as its not assumable " -ForegroundColor Red
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
        $ValidFederatedAccounts += "$AccountID`t$AccountName"
        #Write-Host "Found Account Details:    $AccountID      $AccountName" 
        $Count ++
        Write-Host " $Count - Successfully Assumed $RoleToAssume to AWS Account   $AccountID - $AccountName"
        $TotalAccounts ++

        $Found = DeleteLambda $AccountID 
            if(!($Found))
            {
                Write-Host "     No Lambda Functions Found in this account $AccountID" -ForegroundColor Yellow
            }
            else
            {
                Write-Host "     Found Lambda Functions in this account $AccountID" -ForegroundColor Green
            }

        $Found = DeleteCWERule $AccountID 
            if(!($Found))
            {
                Write-Host "     No CWEvent Rules Found in this account" -ForegroundColor Yellow
            }
            else
            {
                Write-Host "     Found Instances in this account" -ForegroundColor Green
            }
	    
	    
	    $Found = DeleteConfigRules $AccountID 
            if(!($Found))
            {
                Write-Host "     No CWEvent Rules Found in this account" -ForegroundColor Yellow
            }
            else
            {
                Write-Host "     Found Instances in this account" -ForegroundColor Green
            }
	    
	    
	    
	    
    }
}






