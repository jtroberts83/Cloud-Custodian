#!/bin/bash

####################################################################################################################################
###
###     Script Written By:  Jamison Roberts 5-18-2020 
###
###     Description:  This script will use the current install of custodian AND c7n-org (optional) to parse
###                   out all resource types from the custodian schema.  Then it builds an expanded schema txt file (optional).
###                   Then the script will use the array of c7n resource types to generate a bare-bone policy for each resource 
###                   type, then it saves all policies to a .yaml file and runs c7n-org (or custodian) using that new policy file.
###                   Once all the policies have ran, it will generate reports for each resource type saving them as seperate csvs.
###                   Once all the reports have been generated the script will upload all the csvs and expanded schema file to your 
###                   S3 bucket and then it's done.
###
###     Pre-Reqs: Cloud Custodian and c7n_org (optional) installed, aws cli setup with access to the S3 bucket specified below
###               Please go through the script and update BOTH the c7n-org commands to use your accounts config file and if needed
###               specify which regions you want to run against if not already specified in your accounts config.yaml file. Once 
###               again, make sure to do this for both the custodian/c7n-org RUN and REPORT commands.
####################################################################################################################################


# S3 Bucket Name and Key Path To Upload Expanded Schema and CSV Resource Reports To
S3Bucket='YOUR-S3-BUCKET-NAME-HERE'
S3KeyPath='C7N-Generated-Reports'


# Creates Directories To Save Files To For Uploading To S3
mkdir /tmp/c7n
mkdir /tmp/c7n/policies
mkdir /tmp/c7n/csvs
mkdir /tmp/c7n/jsons


#Exports the custodian schema to a file called schema_list
custodian schema > schema_list


# The folling sed commands remove the resources: and - marks from the schema file so it can be read in as an array
sed -i -e 's/- //g' schema_list
sed -i -e 's/resources://g' schema_list


# Clear our the schema_quick_reference.txt file with a hearder and new line
echo "Cloud Custodian Quick Reference" > schema_quick_ref.txt
echo " " >> schema_quick_ref.txt
echo "Custodian Version:" >> schema_quick_ref.txt
custodian version >> schema_quick_ref.txt


# Reads the cleaned up schema_list file into variable $resourcesArray as an array
readarray resourcesArray < schema_list


echo "Please wait while shemas are expanded"

# For each resource in the schema expand it and save it to the quick reference file
for resourceType in "${resourcesArray[@]}"
do
    #Gets the size of the line so it can skip empty lines
    size=${#resourceType}
    if (( size > 1 )); then
        echo "Expanding -> $resourceType"
        custodian schema $resourceType >> schema_quick_ref.txt
    fi
done


# Copy Quick Ref Doc To Temp C7n Location
cp schema_quick_ref.txt /tmp/c7n/C7n-Expanded-Schema.txt


# Creates a multi-line variable called 'policyTemplate' which has 
# the bones of the cloud custodian policies we want to run
# NOTE: The 'RESTYPE' in the below template will be replaced with the actual resource names later 
read -r -d '' policyTemplate << EOM
- name: report-all-RESTYPEs
  resource: RESTYPE
EOM


# Create/Overwrite our policy yaml file and start it with 'policies:'
echo "policies:" > CustodianScanAllResourceTypesPolicies.yaml


# Loop through each resource type in the $a array
for resourceTypeNew in "${resourcesArray[@]}"
do
    # Get the size of the $resourceTypeNew variable
    size=${#resourceTypeNew}
	
	
    # If the size of the resourceTypeNew variable is greater than 1 proceed
    if (( size > 1 )); then
	    
	# Remove the 'aws.' from in front of the resource (optional)
        resourceTypeNew=$(echo "$resourceTypeNew" | sed 's/aws\.//g')
		
	# Removes any newlines/returns from the resourceTypeNew variable and saves it as $CleanedResourceType
        CleanedResourceType=${resourceTypeNew//[$'\t\r\n']}
        
	# Sets a variable '$tempPolicyTemplate' to the contents of 
	# our $policyTemplate (so we don't overwrite the orginal template)
	tempPolicyTemplate=$policyTemplate
		
	# Replace 'RESTYPE' in the $tempPolicyTemplate with the actual resource name
        tempPolicyTemplate=$(echo "$tempPolicyTemplate" | sed "s/RESTYPE/$CleanedResourceType/g")
		
	# Write out a blank line/newline followed by the contents of $tempPolicyTemplate followed 
	# by another blank line/newline to the file followed by another newline CustodianScanAllResourceTypesPolicies.yaml
        echo "" >> CustodianScanAllResourceTypesPolicies.yaml
        echo "$tempPolicyTemplate" >> CustodianScanAllResourceTypesPolicies.yaml
        echo "" >> CustodianScanAllResourceTypesPolicies.yaml
    fi
done


# Copy the new generated policy file to our /tmp/c7n/policies directory
cp CustodianScanAllResourceTypesPolicies.yaml /tmp/c7n/policies/CustodianScanAllResourceTypesPolicies.yaml


# Now the script executes all the policies in the new generated policy file.
# I use c7n-org here but you can replace 'c7n-org run' with 'custodian run' and
# update the other parameters if you dont use c7n-org
echo "Done Creating Policies File, Now Running The Policies With C7N-ORG"
c7n-org run -s . -c config-Regional.yaml -u /tmp/c7n/policies/CustodianScanAllResourceTypesPolicies.yaml
echo "Done Scanning All Resource Types.  Now creating Reports, please wait this will likely take several minutes"


# Loop through each resource type in the $a array
for resourceType in "${resourcesArray[@]}"
do
    # Get the size of the $resourceTypeNew variable
    size=${#resourceType}
	
    # If the size of the resourceTypeNew variable is greater than 1 proceed (makes sure it's not null)
    if (( size > 1 )); then
	
        # Remove the 'aws.' from in front of the resource (optional)
        resourceTypeNew=$(echo "$resourceType" | sed 's/aws\.//g')
		
	# Removes any newlines/returns from the resourceTypeNew variable and saves it as $CleanedResourceType
        CleanedResourceType=${resourceTypeNew//[$'\t\r\n']}
		
	# Runs a c7n-org REPORT command here which uses the findings of our above policies run
	# to generate csv files which get saved to /tmp/c7n/csvs/
        echo "Running Report For Resource: $CleanedResourceType"
	
	# Create the CSV Reports
        c7n-org report -s . -c config-Regional.yaml -u /tmp/c7n/policies/CustodianScanAllResourceTypesPolicies.yaml --resource $CleanedResourceType --output /tmp/c7n/csvs/$CleanedResourceType.csv --format csv
	
	# Create the JSON Reports
	c7n-org report -s . -c config-Regional.yaml -u /tmp/c7n/policies/CustodianScanAllResourceTypesPolicies.yaml --resource $CleanedResourceType --output /tmp/c7n/jsons/$CleanedResourceType.json --format json
    fi
done


# All reports have been generated now so upload all the files in /tmp/c7n/ to our S3 bucket name (specified at top of script)
echo "Syncing Files To S3 Bucket $S3Bucket"
aws s3 sync /tmp/c7n s3://$S3Bucket/$S3KeyPath/



echo "Done Running Script.  All the files are in your $S3Bucket S3 Bucket in the $S3KeyPath folder"
