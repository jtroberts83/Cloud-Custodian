#!/bin/bash

#Exports the custodian schema to a file called schema_list
custodian schema > schema_list

# The folling sed commands remove the resources: and - marks from the schema file so it can be read in as an array
sed -i -e 's/- //g' schema_list
sed -i -e 's/resources://g' schema_list

# Clear our the schema_quick_reference.txt file with a hearder and new line
echo "Cloud Custodian Quick Reference" > schema_quick_ref.txt
echo " " >> schema_quick_ref.txt

# Reads the cleaned up schema_list file into variable $a as an array
readarray a < schema_list

echo "Please wait while shemas are expanded"

# For each resource in the schema expand it and save it to the quick reference file
for resourceName in "${a[@]}"
do
    #Gets the size of the line so it can skip empty lines
    size=${#resourceName}
    if (( size > 1 )); then
        echo "Expanding -> $resourceName"
        custodian schema $resourceName >> schema_quick_ref.txt
    fi
done
cat schema_quick_ref.txt
