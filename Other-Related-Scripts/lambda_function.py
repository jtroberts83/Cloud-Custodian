import boto3
import csv
from botocore.client import Config


bucketname='YOUR-S3-BUCKET'
key="OpenSGs.txt"
bucketregion="us-east-1"

ec2 = boto3.client('ec2')
s3 = boto3.client('s3',config=Config(signature_version='s3v4'), region_name=bucketregion)




def lambda_handler(event, context):
    s3resource = boto3.resource('s3', config=Config(signature_version='s3v4'), region_name=bucketregion)
    s3resource.meta.client.download_file(bucketname, key, '/tmp/OpenSGs.txt')
    AllOpenSGs=[]
    f = open('/tmp/OpenSGs.txt', 'r')
    AllOpenSGs = f.read()
    AllOpenSGs = AllOpenSGs.split('\n')
    
    #print("Existing SGS are: %s" % AllOpenSGs)
    response = ec2.describe_security_groups()
    for sg in response['SecurityGroups']:
        IPPermissions=sg['IpPermissions']
        for ingress in IPPermissions:
            IpRanges=ingress['IpRanges']
            for range in IpRanges:
                cidr=range['CidrIp']
                if '0.0.0.0/0' in cidr:
                    print(cidr)
                    sgname=sg['GroupId']
                    AllOpenSGs.append(sgname)
    
    # Creates array of unique values to remove duplicate SGs                
    AllUniqueSGs = list(set(AllOpenSGs))
    
    # Convert the List to a String to avoid S3 errors
    StringOfSGs = '\n'.join(AllUniqueSGs)
    
    # Upload the txt file to S3
    response = s3.put_object(
        Body=StringOfSGs,
        Bucket=bucketname,
        Key=key
    )
    return 'File Has Been Uploaded To S3'
