import boto3
import json
import os
if 'QUEUE_URL' in os.environ:
  QUEUE_URL = os.environ['QUEUE_URL']
else:
  raise Exception("Missing environment variable: QUEUE_URL")
ROLE_ARNS=[
  "arn:aws:iam::<ACCOUNT-NUMBER-HERE:role/Cloud_Custodian_Role"
]
# All regions that allow Lambda
REGION_NAMES = [
  None,
  'ap-northeast-1',
  'ap-northeast-2',
  'ap-south-1',
  'ap-southeast-1',
  'ap-southeast-2',
  'eu-central-1',
  'eu-west-1',
  'eu-west-2',
  'us-east-1',
  'us-east-2',
  'us-west-1',
  'us-west-2',
]
def role_arns():
  return ROLE_ARNS
def insert(role_arn, region_name):
  boto3.client('sqs').send_message(
    QueueUrl=QUEUE_URL,
    MessageBody=json.dumps({
      "role_arn": role_arn,
      "region_name": region_name
    })
  )
def lambda_handler(event=None, context=None):
  for role_arn in role_arns():
    for region_name in REGION_NAMES:
      insert(role_arn, region_name)
if __name__ == '__main__':
  lambda_handler()
