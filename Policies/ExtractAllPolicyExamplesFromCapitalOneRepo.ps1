## put the folder location of your local copy of the Cloud Custodian repo here    
$PathToLocalCopyOfCloudCustodianGitHubRepo = "C:\some-folder-location\cloud-custodian\" 
##    Ex:   $PathToLocalCopyOfCloudCustodianGitHubRepo = "C:\GitHub\Cloud-Custodian\"  Make sure you point to the root of that repo folder

# Set initial counter
$PolicyCount = 0

#Remove old PolicyExample.txt file if it exists
if(Test-Path -Path "C:\temp\PolicyExamples.txt")
{
    Remove-Item -Path "C:\temp\PolicyExamples.txt"       
}



# Get the list of files in the Cloud Custodian repo recursively
Get-ChildItem "$PathToLocalCopyOfCloudCustodianGitHubRepo" -Filter *.py -Recurse | 
Foreach-Object {
    #Reads in the .py file
    $PolicyFile = Get-Content $_.FullName -Raw
    $StartExampleIndex = 0
    $EndExampleIndex = 0

    #As long as there are more examples, keep iterating through
    while(($StartExampleIndex -ge 0) -and ($PolicyFile))
    {
        # Most examples are encased in triple quotes """ so find the start and end position of those """ and extract the string inbetween them
        $StartExampleIndex = $PolicyFile.IndexOf('"""',($StartExampleIndex + 1))
        if($StartExampleIndex -ge 0)
        {
            $EndExampleIndex = $PolicyFile.IndexOf('"""', ($StartExampleIndex + 3))
            $ExampleStringLength = $null
            $ExampleStringLength = ($EndExampleIndex - $StartExampleIndex)
            if($ExampleStringLength -gt 15)
            {
                $Example = $null
                $Example = $PolicyFile.Substring($StartExampleIndex, ($ExampleStringLength + 3))
                if(($Example.Contains("example")) -and ($Example.Contains("code-block: yaml")))
                {
                    $PolicyCount++
                    Write-Host "`n $Example" -ForegroundColor Green
                    # Write the examples to C:\temp\PolicyExamples.txt file
                    Write-Output "`r`n`r`n $PolicyCount ##$Example " | Out-File "C:\temp\PolicyExamples.txt" -Append
                }
            }    
        }
    }
 }