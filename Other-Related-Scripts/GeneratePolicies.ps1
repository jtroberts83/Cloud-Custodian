
## List all services that support tagging in the $AWSServicesArray
$AWSServicesArray = @("cloud-directory","cloudhsm-cluster","cloudsearch","dax","directconnect","dynamodb-stream","eks","fsx","fsx-backup","gamelift-build","gamelift-fleet","glue-dev-endpoint","hsm","hsm-client","hsm-hapg","iot","lightsail-db","lightsail-elb","lightsail-instance","ops-item","opswork-cm","opswork-stack","r53domain","rds-reserved","sagemaker-endpoint","sagemaker-endpoint-config","sagemaker-job","sagemaker-transform-job","shield-attack","shield-protection","snowball-cluster","ssm-activation","storage-gateway","streaming-distribution","user-pool","waf-regional")

$AllPoliciesArray = @("policies:`r`n`r`n")

$template = @'
- name: <SERVICE_HERE>
  resource: <SERVICE_HERE>
  filters:
         PUT YOUR TAGGING FILTERS HERE
      
'@

foreach($Service in $AWSServicesArray)
{
    $ServicePolicy = $template
    $ServicePolicy = $ServicePolicy -replace "<SERVICE_HERE>","$Service"
    
    $AllPoliciesArray += $ServicePolicy
}


$AllPolicies = $AllPoliciesArray -join "`r`n`r`n"

Write-Output $AllPolicies | Out-File C:\temp\AllResourceTaggingPolicies.yaml
